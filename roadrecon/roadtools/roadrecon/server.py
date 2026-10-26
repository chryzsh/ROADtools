from flask import Flask, request, jsonify, abort, send_from_directory, redirect, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from marshmallow_sqlalchemy import ModelConverter
from marshmallow import fields
from roadtools.roadlib.metadef.database import Base, User, JSON, Group, DirectoryRole, \
ServicePrincipal, AppRoleAssignment, TenantDetail, Application, Device, \
OAuth2PermissionGrant, AuthorizationPolicy, DirectorySetting, AdministrativeUnit, \
RoleDefinition, Policy, lnk_policy_user_include_allusers, PIMgovernanceResource, \
PIMgovernanceRoleAssignment, PIMgovernanceRoleDefinition, PIMgovernanceRoleSetting, \
PIMgovernanceRoleSettingV2, IGaccessPackageAssignmentPolicy, IGaccessPackage, \
IGaccessPackageResourceRoleScope, IGaccessPackageResourceRole, IGaccessPackageResourceScope, \
AZroleDefinition, AZroleAssignment, AZsubscription, AZroleEligibilityScheduleInstance
import os
import base64
import zlib
import argparse
import json
from sqlalchemy import func, and_, or_, select, desc, asc, cast, collate, inspect
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload, load_only
import mimetypes

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# This will get initialized later on
db = None
ma = Marshmallow(app)

mimetypes.add_type('application/javascript', '.js')

# Allow CORS requests from Angular if it's running in develop mode
CORS(app, origins=['http://127.0.0.1:4200', 'http://localhost:4200', 'http://localhost:5000'])

# Model definitions that include a custom JSON type, which doesn't get converted
class RTModelConverter(ModelConverter):
    SQLA_TYPE_MAPPING = dict(
        list(ModelConverter.SQLA_TYPE_MAPPING.items()) +
        [(JSON, fields.Raw)]
    )

# Our custom model schema which uses the model converter from above
class RTModelSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model_converter = RTModelConverter

# Schemas for objects
# For each object type there is an <objectname>Schema and <plural objectname>Schema
# the plural version is for lists of objects (doesn't include all fields)
# the regular version includes all possible fields based on the SQLAlchemy meta definition
class UsersSchema(ma.Schema):
    class Meta:
        model = User
        fields = ('objectId', 'objectType', 'userPrincipalName', 'displayName', 'mail', 'lastDirSyncTime', 'accountEnabled', 'department', 'lastPasswordChangeDateTime', 'jobTitle', 'mobile', 'dirSyncEnabled', 'strongAuthenticationDetail', 'userType', 'searchableDeviceKey')

class DevicesSchema(ma.Schema):
    class Meta:
        model = User
        fields = ('objectId', 'objectType', 'accountEnabled', 'displayName', 'deviceManufacturer', 'deviceModel', 'deviceOSType', 'deviceOSVersion', 'deviceTrustType', 'isCompliant', 'deviceId', 'isManaged', 'isRooted', 'dirSyncEnabled')

class DirectoryRoleSchema(ma.Schema):
    class Meta:
        model = DirectoryRole
        fields = ('displayName', 'description')

class OAuth2PermissionGrantsSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = OAuth2PermissionGrant

class AppRoleAssignmentsSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = AppRoleAssignment

class GroupsSchema(ma.Schema):
    class Meta:
        model = Group
        fields = ('displayName', 'description', 'createdDateTime', 'dirSyncEnabled', 'objectId', 'objectType', 'groupTypes', 'mail', 'isPublic', 'isAssignableToRole', 'membershipRule')

class AdministrativeUnitsSchema(ma.Schema):
    class Meta:
        model = AdministrativeUnit
        fields = ('displayName', 'description', 'createdDateTime', 'objectId', 'objectType', 'membershipType', 'membershipRule')

class SimpleServicePrincipalsSchema(ma.Schema):
    """
    Simple ServicePrincipalSchema to prevent looping relationships with serviceprincipals
    owning other serviceprincipals
    """
    class Meta:
        model = ServicePrincipal
        fields = ('objectId', 'objectType', 'displayName', 'servicePrincipalType')

class ServicePrincipalsSchema(ma.Schema):
    class Meta:
        model = ServicePrincipal
        fields = ('objectId', 'objectType', 'displayName', 'appDisplayName', 'appRoleAssignmentRequired', 'appId', 'appOwnerTenantId', 'publisherName', 'replyUrls', 'appRoles', 'microsoftFirstParty', 'isDirSyncEnabled', 'oauth2Permissions', 'passwordCredentials', 'keyCredentials', 'ownerUsers', 'ownerServicePrincipals', 'accountEnabled', 'servicePrincipalType')
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(SimpleServicePrincipalsSchema, many=True)

class ApplicationsSchema(ma.Schema):
    class Meta:
        model = Application
        fields = ('objectId', 'objectType', 'displayName', 'appId', 'appDisplayName', 'oauth2AllowIdTokenImplicitFlow', 'availableToOtherTenants', 'publisherDomain', 'replyUrls', 'appRoles', 'publicClient', 'oauth2AllowImplicitFlow', 'oauth2Permissions', 'homepage', 'passwordCredentials', 'keyCredentials', 'ownerUsers', 'ownerServicePrincipals')
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(SimpleServicePrincipalsSchema, many=True)

class DirectoryRolesSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = DirectoryRole
    memberUsers = fields.Nested(UsersSchema, many=True)
    memberServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    memberGroups = fields.Nested(GroupsSchema, many=True)

class PIMgovernanceRoleSettingSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceRoleSetting

class PIMgovernanceRoleSettingV2Schema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceRoleSettingV2

class PIMgovernanceRoleDefinitionsSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceRoleDefinition

    roleSettings = fields.Nested(PIMgovernanceRoleSettingSchema, many=True)
    roleSettingsv2 = fields.Nested(PIMgovernanceRoleSettingV2Schema, many=True)

class PIMgovernanceResourcesSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceResource

class PIMgovernanceRoleAssignmentsSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceRoleAssignment

    roleDefinition = fields.Nested(PIMgovernanceRoleDefinitionsSchema)
    resource = fields.Nested(PIMgovernanceResourcesSchema)

# include members
class PIMgovernanceRoleAssignmentsWithMembersSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceRoleAssignment

    subjectUser = fields.Nested(UsersSchema, many=True)
    subjectGroup = fields.Nested(GroupsSchema, many=True)
    subjectServicePrincipal = fields.Nested(ServicePrincipalsSchema, many=True)

class PIMgovernanceRoleDefinitionSchema(RTModelSchema):
    class Meta:
        model = PIMgovernanceRoleDefinition

class PIMgovernanceRoleDefinitionWithAssignmentsSchema(RTModelSchema):
    class Meta:
        model = PIMgovernanceRoleDefinition
    roleAssignments = fields.Nested(PIMgovernanceRoleAssignmentsWithMembersSchema, many=True)
    roleSettings = fields.Nested(PIMgovernanceRoleSettingSchema, many=True)
    roleSettingsv2 = fields.Nested(PIMgovernanceRoleSettingV2Schema, many=True)

# for individual resources, with more detail
class PIMgovernanceResourceSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceResource
    roleDefinitions = fields.Nested(PIMgovernanceRoleDefinitionWithAssignmentsSchema, many=True)


class IGaccessPackageResourceRolesSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = IGaccessPackageResourceRole

class IGaccessPackageResourceScopesSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = IGaccessPackageResourceScope

class IGaccessPackageResourceRoleScopesSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = IGaccessPackageResourceRoleScope
    role = fields.Nested(IGaccessPackageResourceRolesSchema, many=True)
    scope = fields.Nested(IGaccessPackageResourceScopesSchema, many=True)

class IGaccessPackagesSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = IGaccessPackage

    resourceRoleScopes = fields.Nested(IGaccessPackageResourceRoleScopesSchema, many=True)

class IGaccessPackageAssignmentPolicysSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = IGaccessPackageAssignmentPolicy
    accessPackage = fields.Nested(IGaccessPackagesSchema)

class AZroleDefinitionSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AZroleDefinition

class AZroleAssignmentsSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AZroleAssignment
    role = fields.Nested(AZroleDefinitionSchema)

class AZeligibleRoleAssignmentsSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AZroleEligibilityScheduleInstance
    role = fields.Nested(AZroleDefinitionSchema)

class UserSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = User
    memberOf = fields.Nested(GroupsSchema, many=True)
    memberOfRole = fields.Nested(DirectoryRoleSchema, many=True)
    ownedDevices = fields.Nested(DevicesSchema, many=True)
    ownedServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    ownedApplications = fields.Nested(ApplicationsSchema, many=True)
    ownedGroups = fields.Nested(GroupsSchema, many=True)
    pimRoleAssignments = fields.Nested(PIMgovernanceRoleAssignmentsSchema, many=True)

class DeviceSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Device
    memberOf = fields.Nested(GroupsSchema, many=True)
    owner = fields.Nested(UsersSchema, many=True)

class GroupSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Group
    memberOf = fields.Nested(GroupsSchema, many=True)
    memberGroups = fields.Nested(GroupsSchema, many=True)
    memberUsers = fields.Nested(UsersSchema, many=True)
    memberOfRole = fields.Nested(DirectoryRoleSchema, many=True)
    memberDevices = fields.Nested(DevicesSchema, many=True)
    memberServicePrincipals = fields.Nested(SimpleServicePrincipalsSchema, many=True)
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(SimpleServicePrincipalsSchema, many=True)
    pimRoleAssignments = fields.Nested(PIMgovernanceRoleAssignmentsSchema, many=True)

class AdministrativeUnitSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AdministrativeUnit
    memberGroups = fields.Nested(GroupsSchema, many=True)
    memberUsers = fields.Nested(UsersSchema, many=True)
    memberDevices = fields.Nested(DevicesSchema, many=True)

class ServicePrincipalSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = ServicePrincipal
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    memberOfRole = fields.Nested(DirectoryRoleSchema, many=True)
    memberOf = fields.Nested(GroupSchema, many=True)
    oauth2PermissionGrants = fields.Nested(OAuth2PermissionGrantsSchema, many=True)
    appRolesAssigned = fields.Nested(AppRoleAssignmentsSchema, many=True)
    appRolesAssignedTo = fields.Nested(AppRoleAssignmentsSchema, many=True)

class ApplicationSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Application
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)

class TenantDetailSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = TenantDetail

class DirectorySettingSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = DirectorySetting

class AuthorizationPolicySchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AuthorizationPolicy

# Instantiate all schemas
user_schema = UserSchema()
device_schema = DeviceSchema()
group_schema = GroupSchema()
group_schema_simple = GroupsSchema()
application_schema = ApplicationSchema()
td_schema = TenantDetailSchema()
ds_schema = DirectorySettingSchema()
serviceprincipal_schema = ServicePrincipalSchema()
administrativeunit_schema = AdministrativeUnitSchema()
authorizationpolicy_schema = AuthorizationPolicySchema(many=True)
users_schema = UsersSchema(many=True)
devices_schema = DevicesSchema(many=True)
groups_schema = GroupsSchema(many=True)
applications_schema = ApplicationsSchema(many=True)
serviceprincipals_schema = ServicePrincipalsSchema(many=True)
directoryroles_schema = DirectoryRolesSchema(many=True)
administrativeunits_schema = AdministrativeUnitsSchema(many=True)
pimgovernanceroleassignments_schema = PIMgovernanceRoleAssignmentsSchema(many=True)
igaccesspackagepolicys_schema = IGaccessPackageAssignmentPolicysSchema(many=True)
azroleassignments_schema = AZroleAssignmentsSchema(many=True)
azeligibleroleassignments_schema = AZeligibleRoleAssignmentsSchema(many=True)
pimresource_schema = PIMgovernanceResourceSchema()

def list_columns(model, schema):
    '''
    Columns of model that are output by schema. Used with load_only on lists,
    so the other columns (mostly large JSON fields) are not loaded and decoded.
    '''
    return [getattr(model, field) for field in schema.fields if field in model.__table__.columns]

@app.route("/")
def get_index():
    return send_file('dist_gui/index.html')

@app.errorhandler(404)
def page_not_found(error):
    # Might be a valid angular page, serve that
    if not '.' in request.path and not request.path.startswith('/api/'):
        return send_file('dist_gui/index.html')
    return '404 - Page was not found', 404

@app.route("/<path:path>", methods=["GET"])
def get_gui(path):
    return send_from_directory('dist_gui', path)

@app.route("/api/users", methods=["GET"])
def get_users():
    all_users = db.session.query(User).options(load_only(*list_columns(User, users_schema))).all()
    result = users_schema.dump(all_users)
    return jsonify(result)

@app.route("/api/paged/users", methods=["GET"])
def get_paged_users():
    return query_all_items(request, users_schema, User, ["userPrincipalName", "displayName", "objectId"])

@app.route("/api/users/<id>", methods=["GET"])
def user_detail(id):
    user = db.session.get(User,id)
    if not user:
        abort(404)
    return user_schema.jsonify(user)

@app.route("/api/devices", methods=["GET"])
def get_devices():
    all_devices = db.session.query(Device).options(load_only(*list_columns(Device, devices_schema))).all()
    result = devices_schema.dump(all_devices)
    return jsonify(result)

@app.route("/api/paged/devices", methods=["GET"])
def get_paged_devices():
    return query_all_items(request, devices_schema, Device, ["displayName", "objectId", "deviceId"])

@app.route("/api/devices/<id>", methods=["GET"])
def device_detail(id):
    device = db.session.get(Device, id)
    if not device:
        abort(404)
    return device_schema.jsonify(device)

@app.route("/api/users/<id>/groups", methods=["GET"])
def user_groups(id):
    user = db.session.get(User, id)
    if not user:
        abort(404)
    result = groups_schema.dump(user.memberOf)
    return jsonify(result)

@app.route("/api/users/<id>/pimassignments", methods=["GET"])
def user_pimassignments(id):
    user = db.session.get(User, id)
    if not user:
        abort(404)
    assignments = []
    for group in user.memberOf:
        assignments += group.pimRoleAssignments
    result = pimgovernanceroleassignments_schema.dump(assignments)
    return jsonify(result)

@app.route("/api/users/<id>/accesspackages", methods=["GET"])
def user_accesspackages(id):
    user = db.session.get(User, id)
    if not user:
        abort(404)
    packages = [] + user.accessPackagePolicies
    for group in user.memberOf:
        packages += group.accessPackagePolicies
    if user.userType != 'Guest':
        alluserpackages = db.session.query(IGaccessPackageAssignmentPolicy).where(IGaccessPackageAssignmentPolicy.allowedTargetScope.in_(['allDirectoryUsers','allMemberUsers'])).all()
    else:
        alluserpackages = db.session.query(IGaccessPackageAssignmentPolicy).where(IGaccessPackageAssignmentPolicy.allowedTargetScope.in_(['allDirectoryUsers','allExternalUsers'])).all()
    packages += alluserpackages
    result = igaccesspackagepolicys_schema.dump(packages)
    return jsonify(result)

def prefetch_group_tree(groups):
    '''
    Load memberOf and azRoleAssignments of the groups and of all groups they
    are nested in, with one query per nesting level, so add_ra_recursive does
    not need a query per group. Returns the loaded groups, the caller has to
    keep this list until it is done since the session only keeps weak references.
    '''
    loaded = list(groups)
    seen = {group.objectId for group in groups}
    frontier = seen
    while frontier:
        level = query_by_ids((Group,), Group.objectId, frontier,
                             (load_only(Group.objectId),
                              selectinload(Group.memberOf).load_only(Group.objectId),
                              selectinload(Group.azRoleAssignments).selectinload(AZroleAssignment.role))).values()
        loaded += level
        frontier = {parent.objectId for group in level for parent in group.memberOf} - seen
        seen |= frontier
    return loaded

def add_ra_recursive(group, roles, processedgroups):
    roles += group.azRoleAssignments
    if group.objectId not in processedgroups:
        processedgroups.add(group.objectId)
        for sgroup in group.memberOf:
            add_ra_recursive(sgroup, roles, processedgroups)

@app.route("/api/users/<id>/azroleassignments", methods=["GET"])
def user_azroleassignments(id):
    user = db.session.get(User, id)
    if not user:
        abort(404)
    roles = [] + user.azRoleAssignments
    processedgroups = set()
    loaded = prefetch_group_tree(user.memberOf)
    for group in user.memberOf:
        add_ra_recursive(group, roles, processedgroups)

    result = azroleassignments_schema.dump(roles)
    return jsonify(result)

def get_application(aid):
    if isinstance(aid, list):
        return db.session.query(ServicePrincipal).filter(ServicePrincipal.appId.in_(aid)).all()
    else:
        return db.session.query(ServicePrincipal).filter(ServicePrincipal.appId == aid).first()

def parse_appcrit(crit):
    ot = []
    for ctype, clist in crit.items():
        if ctype == 'Acrs':
            ot.append({
                'objectType':'SPECIAL',
                'objectId': None,
                'displayName': 'Action: ' +  ', '.join([action for action in clist])
            })
        elif ctype == 'NetworkAccess':
            # clist should be a dict, for example {"TrafficProfiles":"Internet"}
            ot.append({
                'objectType':'SPECIAL',
                'objectId': None,
                'displayName': 'Network access: ' + ', '.join([f"{action}: {target}" for action, target in clist.items()])
            })
        else:
            if 'All' in clist:
                ot.append({
                    'objectType':'SPECIAL',
                    'objectId': None,
                    'displayName': 'All resources'
                })
                break
            if 'None' in clist:
                ot.append({
                    'objectType':'SPECIAL',
                    'objectId': None,
                    'displayName': 'No resources (policy never applies)'
                })
                break
            if 'Office365' in clist:
                ot.append({
                    'objectType':'SPECIAL',
                    'objectId': None,
                    'displayName': 'All Office 365 applications'
                })
            if 'MicrosoftAdminPortals' in clist:
                ot.append({
                    'objectType':'SPECIAL',
                    'objectId': None,
                    'displayName': 'All Microsoft admin portals'
                })
            objects = get_application(clist)
            if objects is not None:
                if len(objects) > 0:
                    if ctype == 'Applications':
                        for app in objects:
                            ot.append({
                                'objectType':'ServicePrincipal',
                                'objectId': app.objectId,
                                'displayName': app.displayName
                            })
    return ot

def parse_scope(cond):
    if not 'Applications' in cond:
        return
    ucond = cond['Applications']
    out = {'include':[],'exclude':[]}
    for icrit in ucond['Include']:
        out['include'] += parse_appcrit(icrit)
    if 'Exclude' in ucond:
        for icrit in ucond['Exclude']:
            out['exclude'] += parse_appcrit(icrit)
    return out

def process_user_policies(alluser_policies, user):
    policies = []
    for policy in user.policiesIncluded:
        detail = json.loads(policy.policyDetail[0])
        if detail['State'] != 'Enabled' or policy in user.policiesExcluded:
            continue
        else:
            policies.append({
                'objectId': policy.objectId,
                'policyDetail': detail,
                'displayName': policy.displayName,
                'policyScope': parse_scope(detail['Conditions'])
            })
    for policy in alluser_policies:
        detail = json.loads(policy.policyDetail[0])
        if detail['State'] != 'Enabled' or policy in user.policiesExcluded:
            continue
        else:
            policies.append({
                'objectId': policy.objectId,
                'policyDetail': detail,
                'displayName': policy.displayName,
                'policyScope': parse_scope(detail['Conditions'])
            })
    return policies

@app.route("/api/users/<id>/policies", methods=["GET"])
def user_policies(id):
    user = db.session.get(User, id)
    if not user:
        abort(404)

    aup_ids = [record[0] for record in db.session.query(lnk_policy_user_include_allusers).all()]

    alluser_policies = db.session.query(Policy).filter(Policy.objectId.in_(aup_ids)).all()
    return jsonify(process_user_policies(alluser_policies, user))

def parse_compressed_cidr(detail):
    if not 'CompressedCidrIpRanges' in detail:
        return ''
    compressed = detail['CompressedCidrIpRanges']
    b = base64.b64decode(compressed)
    cstr = zlib.decompress(b, -zlib.MAX_WBITS)
    decoded_cidrs = cstr.decode().split(",")
    return decoded_cidrs

@app.route("/api/policies/locations", methods=["GET"])
def policies_locations():
    locs = {}
    for policy in db.session.query(Policy).filter(Policy.policyType == 6).order_by(Policy.displayName):
        loc = {}
        loc['displayName'] = policy.displayName
        # Old format: one record can hold several known networks, one per policyDetail entry
        knownnetworks = []

        for pdetail in policy.policyDetail:
            detaildata = json.loads(pdetail)
            if 'KnownNetworkPolicies' in detaildata:
                knownnetworks.append(detaildata['KnownNetworkPolicies'])

        if not knownnetworks:
            # New format
            detail = json.loads(policy.policyDetail[0])
            if not detail:
                continue

            loc['trusted'] = ("trusted" in detail.get("Categories","") if detail.get("Categories") else False)
            loc['appliesToUnknownCountry'] = str(detail.get("ApplyToUnknownCountry")) if detail.get("ApplyToUnknownCountry") is not None else False
            loc['ipRanges'] = parse_compressed_cidr(detail)
            loc['categories'] = detail.get("Categories") if detail.get("Categories") is not None else ""
            loc['countryCodes'] =  detail.get("CountryIsoCodes") if detail.get("CountryIsoCodes") else None
            locs[policy.policyIdentifier] = loc
        else:
            # Old format
            for detail in knownnetworks:
                if not detail:
                    continue
                loc = {}
                loc['displayName'] = detail.get("NetworkName")
                loc['trusted'] = ("trusted" in detail.get("Categories","") if detail.get("Categories") else False)
                loc['appliesToUnknownCountry'] = str(detail.get("ApplyToUnknownCountry")) if detail.get("ApplyToUnknownCountry") is not None else False
                loc['ipRanges'] = detail.get('CidrIpRanges') if detail.get("CidrIpRanges") else ""
                loc['categories'] = detail.get("Categories") if detail.get("Categories") is not None else ""
                loc['countryCodes'] =  detail.get("CountryIsoCodes") if detail.get("CountryIsoCodes") else None
                locs[detail.get("NetworkId")] = loc
    return jsonify(locs)

@app.route("/api/groups", methods=["GET"])
def get_groups():
    all_groups = db.session.query(Group).options(load_only(*list_columns(Group, groups_schema))).all()
    result = groups_schema.dump(all_groups)
    return jsonify(result)

@app.route("/api/paged/groups", methods=["GET"])
def get_paged_groups():
    return query_all_items(request, groups_schema, Group, ["displayName", "objectId"])

@app.route("/api/groups/<id>", methods=["GET"])
def group_detail(id):
    group = db.session.get(Group, id)
    if not group:
        abort(404)
    return group_schema.jsonify(group)

@app.route("/api/groups/<id>/pimresource", methods=["GET"])
def group_pimresource(id):
    group = db.session.get(Group, id)
    if not group or not group.pimResource:
        abort(404)
    return pimresource_schema.jsonify(group.pimResource[0])

@app.route("/api/groups/<id>/azroleassignments", methods=["GET"])
def group_azroleassignments(id):
    group = db.session.get(Group, id)
    if not group:
        abort(404)
    roles = []
    processedgroups = set()
    loaded = prefetch_group_tree([group])
    add_ra_recursive(group, roles, processedgroups)

    result = azroleassignments_schema.dump(roles)
    return jsonify(result)

@app.route("/api/groupresolve/<id>", methods=["GET"])
def group_detail_simple(id):
    group = db.session.get(Group, id)
    if not group:
        abort(404)
    return group_schema_simple.jsonify(group)

@app.route("/api/administrativeunits", methods=["GET"])
def get_administrativeunits():
    all_administrativeunits = db.session.query(AdministrativeUnit).all()
    result = administrativeunits_schema.dump(all_administrativeunits)
    return jsonify(result)

@app.route("/api/administrativeunits/<id>", methods=["GET"])
def administrativeunit_detail(id):
    administrativeunit = db.session.get(AdministrativeUnit, id)
    if not administrativeunit:
        abort(404)
    return administrativeunit_schema.jsonify(administrativeunit)

@app.route("/api/serviceprincipals", methods=["GET"])
def get_sps():
    # Load the owners for all SPs at once instead of one query per SP
    all_sps = db.session.query(ServicePrincipal).options(
        load_only(*list_columns(ServicePrincipal, serviceprincipals_schema)),
        selectinload(ServicePrincipal.ownerUsers).load_only(*list_columns(User, users_schema)),
        selectinload(ServicePrincipal.ownerServicePrincipals)).all()
    return serviceprincipals_schema.jsonify(all_sps)

@app.route("/api/serviceprincipals/<id>", methods=["GET"])
def sp_detail(id):
    sp = db.session.get(ServicePrincipal, id)
    if not sp:
        abort(404)
    return serviceprincipal_schema.jsonify(sp)

@app.route("/api/serviceprincipals/<id>/azroleassignments", methods=["GET"])
def serviceprincipals_azroleassignments(id):
    serviceprincipals = db.session.get(ServicePrincipal, id)
    if not serviceprincipals:
        abort(404)
    roles = [] + serviceprincipals.azRoleAssignments
    processedgroups = set()
    loaded = prefetch_group_tree(serviceprincipals.memberOf)
    for group in serviceprincipals.memberOf:
        add_ra_recursive(group, roles, processedgroups)

    result = azroleassignments_schema.dump(roles)
    return jsonify(result)

@app.route("/api/serviceprincipals-by-appid/<id>", methods=["GET"])
def sp_detail_by_appid(id):
    sp = db.session.query(ServicePrincipal).filter(ServicePrincipal.appId == id).first()
    if not sp:
        abort(404)
    return serviceprincipal_schema.jsonify(sp)

@app.route("/api/applications-by-appid/<id>", methods=["GET"])
def app_detail_by_appid(id):
    sp = db.session.query(Application).filter(Application.appId == id).first()
    if not sp:
        abort(404)
    return application_schema.jsonify(sp)

@app.route("/api/applications", methods=["GET"])
def get_applications():
    all_applications = db.session.query(Application).options(
        load_only(*list_columns(Application, applications_schema)),
        selectinload(Application.ownerUsers).load_only(*list_columns(User, users_schema)),
        selectinload(Application.ownerServicePrincipals)).all()
    result = applications_schema.dump(all_applications)
    return jsonify(result)

@app.route("/api/mfa", methods=["GET"])
def get_mfa():
    # First get all users with per-user MFA
    # per_user = db.session.query(AppRoleAssignment).filter(AppRoleAssignment.resourceDisplayName == "MicrosoftAzureActiveAuthn" and AppRoleAssignment.principalType == "User").all()
    # enabledusers = []
    # for approle in per_user:
    #     enabledusers.append(approle.principalId)

    # Filter out mailbox-only users by default
    all_mfa = db.session.execute(select(User).options(load_only(
        User.objectId, User.displayName, User.userPrincipalName, User.accountEnabled,
        User.strongAuthenticationDetail, User.searchableDeviceKey)).where(
        or_(User.cloudMSExchRecipientDisplayType is None,
            and_(
                User.cloudMSExchRecipientDisplayType != 0,
                User.cloudMSExchRecipientDisplayType != 7,
                User.cloudMSExchRecipientDisplayType != 18
            )
        )
    ))
    out = []
    for user, in all_mfa: # pylint: disable=E1133
        mfa_methods = len(user.strongAuthenticationDetail['methods'])
        methods = [method['methodType'] for method in user.strongAuthenticationDetail['methods']]
        has_app = 'PhoneAppOTP' in methods or 'PhoneAppNotification' in methods
        has_phonenr = 'OneWaySms' in methods or 'TwoWayVoiceMobile' in methods
        has_fido = 'FIDO' in [key['usage'] for key in user.searchableDeviceKey]
        perusermfa = None
        if len(user.strongAuthenticationDetail['requirements']) > 0:
            perusermfa = user.strongAuthenticationDetail['requirements'][0]['state']
        out.append({
            'objectId': user.objectId,
            'displayName': user.displayName,
            'userPrincipalName': user.userPrincipalName,
            'mfamethods': mfa_methods,
            'accountEnabled': user.accountEnabled,
            'perusermfa': perusermfa,
            'has_app': has_app,
            'has_phonenr': has_phonenr,
            'has_fido': has_fido,
            'strongAuthenticationDetail': user.strongAuthenticationDetail,
            'searchableDeviceKey': user.searchableDeviceKey
        })
    return jsonify(out)

@app.route("/api/applications/<id>", methods=["GET"])
def application_detail(id):
    application = db.session.get(Application, id)
    if not application:
        abort(404)
    return application_schema.jsonify(application)

def query_by_ids(entities, idcolumn, ids, options=()):
    '''
    Query objects or columns where idcolumn is one of ids, in chunks to
    stay below the bound parameter limit. Returns a dict of id -> row.
    Used to load all objects referenced by a list in one go instead of
    one query per object.
    '''
    ids = list(ids)
    result = {}
    for i in range(0, len(ids), 500):
        query = db.session.query(*entities).filter(idcolumn.in_(ids[i:i+500])).options(*options)
        for row in query:
            result[getattr(row, idcolumn.key)] = row
    return result

def resolve_objectids(oids):
    '''
    Find the object type of each objectId and dump it with the matching list schema.
    Returns a dict of objectId -> (type, dump, object), objects that are not found are left out.
    Types are checked in the same order as the GUI did before: User, ServicePrincipal, Group,
    Device, Application.
    '''
    sp_owners = (selectinload(ServicePrincipal.ownerUsers), selectinload(ServicePrincipal.ownerServicePrincipals))
    lookups = (
        ('User', User, users_schema, ()),
        ('ServicePrincipal', ServicePrincipal, serviceprincipals_schema, sp_owners),
        # Group members are needed to expand role assignments to groups
        ('Group', Group, groups_schema, (selectinload(Group.memberUsers).load_only(*list_columns(User, users_schema)),
                                         selectinload(Group.memberServicePrincipals).selectinload(ServicePrincipal.ownerUsers),
                                         selectinload(Group.memberServicePrincipals).selectinload(ServicePrincipal.ownerServicePrincipals))),
        ('Device', Device, devices_schema, ()),
        ('Application', Application, applications_schema, (selectinload(Application.ownerUsers), selectinload(Application.ownerServicePrincipals))),
    )
    remaining = set(oids)
    resolved = {}
    for otype, model, schema, options in lookups:
        for oid, obj in query_by_ids((model,), model.objectId, remaining, options).items():
            resolved[oid] = (otype, schema.dump([obj])[0], obj)
        remaining -= resolved.keys()
    return resolved

def get_scope_names(scopes):
    '''
    Look up the display names of all objects referenced in a list of role scopes.
    Returns a dict of model -> {objectId: displayName} for translate_rolescopes.
    '''
    ids = {AdministrativeUnit: set(), Application: set(), ServicePrincipal: set()}
    for scope in scopes:
        parts = scope.split('/')
        if len(parts) > 2:
            if parts[1] == 'administrativeUnits':
                ids[AdministrativeUnit].add(parts[2])
            elif parts[1] == 'applications':
                ids[Application].add(parts[2])
            elif parts[1] == 'servicePrincipals':
                ids[ServicePrincipal].add(parts[2])
        elif len(parts) > 1 and len(parts[1]) > 0:
            ids[ServicePrincipal].add(parts[1])
            ids[Application].add(parts[1])
    names = {}
    for model, mids in ids.items():
        rows = query_by_ids((model.objectId, model.displayName), model.objectId, mids)
        names[model] = {oid: row.displayName for oid, row in rows.items()}
    return names

def translate_rolescopes(scopes, names):
    stypes = []
    sids = []
    snames = []
    for scope in scopes:
        parts = scope.split('/')
        if len(parts) > 2:
            # Includes type
            stype = parts[1]
            sid = parts[2]
            if stype == 'administrativeUnits':
                stype = 'AdministrativeUnit'
                if sid in names[AdministrativeUnit]:
                    sname = f'AU: {names[AdministrativeUnit][sid]}'
                else:
                    sname = 'Unknown administrative unit'
            elif stype == 'applications':
                stype = 'Application'
                if sid in names[Application]:
                    sname = f'Application: {names[Application][sid]}'
                else:
                    sname = 'Unknown application'
            elif stype == 'servicePrincipals':
                stype = 'ServicePrincipal'
                if sid in names[ServicePrincipal]:
                    sname = f'ServicePrincipal: {names[ServicePrincipal][sid]}'
                else:
                    sname = 'Unknown serviceprincipal'
            else:
                sname = f'Unsupported scope type: {scope}'
        elif len(parts) > 1 and len(parts[1]) > 0:
            sid = parts[1]
            if sid in names[ServicePrincipal]:
                stype = 'ServicePrincipal'
                sname = f'ServicePrincipal: {names[ServicePrincipal][sid]}'
            elif sid in names[Application]:
                stype = 'Application'
                sname = f'Application: {names[Application][sid]}'
            else:
                stype = 'Unknown'
                sname = f'Unknown scope type: {scope}'
        else:
            # Scope is entire directory
            stype = 'Directory'
            sname = 'Directory'
            sid = None
        stypes.append(stype)
        snames.append(sname)
        sids.append(sid)
    return stypes, snames, sids


def process_approles(assignments):
    '''
    Convert app role assignments to the format used in the GUI. The resource
    service principals and the principals are loaded with one query per type,
    with only the columns that are needed.
    '''
    resources = query_by_ids((ServicePrincipal.objectId, ServicePrincipal.appRoles),
                             ServicePrincipal.objectId, {ar.resourceId for ar in assignments})
    principals = {}
    for ptype, model in (('ServicePrincipal', ServicePrincipal), ('User', User), ('Group', Group)):
        pids = {ar.principalId for ar in assignments if ar.principalType == ptype}
        principals[ptype] = query_by_ids((model.objectId, model.displayName), model.objectId, pids)
    approles = []
    for ar in assignments:
        rsp = resources.get(ar.resourceId)
        sp = principals[ar.principalType].get(ar.principalId)
        if ar.id == '00000000-0000-0000-0000-000000000000':
            approles.append({'objid':sp.objectId,
                             'ptype':ar.principalType,
                             'pname':sp.displayName,
                             'app':ar.resourceDisplayName,
                             'value':'Default',
                             'desc':'Default Role',
                             'spid':ar.resourceId,
                            })
        else:
            for approle in rsp.appRoles:
                if approle['id'] == ar.id:
                    approles.append({'objid':sp.objectId,
                                     'ptype':ar.principalType,
                                     'pname':sp.displayName,
                                     'app':ar.resourceDisplayName,
                                     'value':approle['value'],
                                     'desc':approle['displayName'],
                                     'spid':ar.resourceId,
                                    })
    return approles

@app.route("/api/approles", methods=["GET"])
def get_approles():
    return jsonify(process_approles(db.session.query(AppRoleAssignment).all()))

@app.route("/api/approles_by_resource/<spid>", methods=["GET"])
def get_approles_by_resource(spid):
    assignments = db.session.query(AppRoleAssignment).filter(AppRoleAssignment.resourceId == spid).all()
    return jsonify(process_approles(assignments))

@app.route("/api/approles_by_principal/<pid>", methods=["GET"])
def get_approles_by_principal(pid):
    assignments = db.session.query(AppRoleAssignment).filter(AppRoleAssignment.principalId == pid).all()
    return jsonify(process_approles(assignments))

@app.route("/api/oauth2permissions", methods=["GET"])
def get_oauth2permissions():
    oauth2permissions = []
    permgrants = db.session.query(OAuth2PermissionGrant).all()
    # Load the referenced service principals and users in one go
    sps = query_by_ids((ServicePrincipal.objectId, ServicePrincipal.displayName), ServicePrincipal.objectId,
                       {pg.clientId for pg in permgrants} | {pg.resourceId for pg in permgrants})
    users = query_by_ids((User.objectId, User.displayName), User.objectId,
                         {pg.principalId for pg in permgrants if pg.consentType == 'Principal'})
    for permgrant in permgrants:
        grant = {}
        rsp = sps.get(permgrant.clientId)
        if permgrant.consentType == 'Principal':
            grant['type'] = 'user'
            user = users.get(permgrant.principalId)
            grant['userid'] = user.objectId
            grant['userdisplayname'] = user.displayName
        else:
            grant['type'] = 'all'
            grant['userid'] = None
            grant['userdisplayname'] = None
        targetapp = sps.get(permgrant.resourceId)
        grant['targetapplication'] = targetapp.displayName
        grant['targetspobjectid'] = targetapp.objectId
        grant['sourceapplication'] = rsp.displayName
        grant['sourcespobjectid'] = rsp.objectId
        grant['expiry'] = permgrant.expiryTime.strftime("%Y-%m-%dT%H:%M:%S")
        grant['scope'] = permgrant.scope
        oauth2permissions.append(grant)
    return jsonify(oauth2permissions)

@app.route("/api/roledefinitions", methods=["GET"])
def get_allroles():
    allroles = []
    roles = db.session.query(RoleDefinition).options(selectinload(RoleDefinition.assignments),
                                                     selectinload(RoleDefinition.eligibleAssignments)).all()
    # Resolve all principals and scope objects up front
    all_assignments = [assignment for role in roles for assignment in role.assignments + role.eligibleAssignments]
    principals = resolve_objectids({assignment.principalId for assignment in all_assignments})
    scope_names = get_scope_names({scope for assignment in all_assignments for scope in assignment.resourceScopes})
    for role in roles:
        roleobj = {
            'objectId': role.objectId,
            'displayName': role.displayName,
            'description': role.description,
            'isBuiltIn': role.isBuiltIn,
            'templateId': role.templateId,
            'assignments': []
        }
        for assignment in role.assignments:
            stypes, snames, sids = translate_rolescopes(assignment.resourceScopes, scope_names)
            aobj = {
                'type': 'assignment',
                'scope': assignment.resourceScopes,
                'scopeTypes': stypes,
                'scopeNames': snames,
                'scopeIds': sids
            }
            principalType, principal, group = principals.get(assignment.principalId, ('Unknown', None, None))
            aobj['principal'] = principal

            roleobj['assignments'].append(aobj)
            if principalType == 'Group':
                for member in group.memberUsers:
                    mp = users_schema.dump([member])[0]
                    mp['displayName'] = f"{principal['displayName']} member: {mp['displayName']}"
                    roleobj['assignments'].append({
                        'type': 'assignment',
                        'scope': assignment.resourceScopes,
                        'scopeTypes': stypes,
                        'scopeNames': snames,
                        'scopeIds': sids,
                        'principal': mp
                    })
                for member in group.memberServicePrincipals:
                    mp = serviceprincipals_schema.dump([member])[0]
                    mp['displayName'] = f"{principal['displayName']} member SP: {mp['displayName']}"
                    roleobj['assignments'].append({
                        'type': 'assignment',
                        'scope': assignment.resourceScopes,
                        'scopeTypes': stypes,
                        'scopeNames': snames,
                        'scopeIds': sids,
                        'principal': mp
                    })

        for assignment in role.eligibleAssignments:
            stypes, snames, sids = translate_rolescopes(assignment.resourceScopes, scope_names)
            aobj = {
                'type': 'eligible',
                'scope': assignment.resourceScopes,
                'scopeTypes': stypes,
                'scopeNames': snames,
                'scopeIds': sids
            }
            principalType, principal, group = principals.get(assignment.principalId, ('Unknown', None, None))
            aobj['principal'] = principal
            roleobj['assignments'].append(aobj)
            if principalType == 'Group':
                for member in group.memberUsers:
                    mp = users_schema.dump([member])[0]
                    mp['displayName'] = f"{principal['displayName']} member: {mp['displayName']}"
                    roleobj['assignments'].append({
                        'type': 'eligible',
                        'scope': assignment.resourceScopes,
                        'scopeTypes': stypes,
                        'scopeNames': snames,
                        'scopeIds': sids,
                        'principal': mp
                    })
                # SPs with eligible assignments probably don't make sense but who knows
                for member in group.memberServicePrincipals:
                    mp = serviceprincipals_schema.dump([member])[0]
                    mp['displayName'] = f"{principal['displayName']} member SP: {mp['displayName']}"
                    roleobj['assignments'].append({
                        'type': 'eligible',
                        'scope': assignment.resourceScopes,
                        'scopeTypes': stypes,
                        'scopeNames': snames,
                        'scopeIds': sids,
                        'principal': mp
                    })
        allroles.append(roleobj)
    return jsonify(allroles)

@app.route("/api/directoryroles", methods=["GET"])
def get_dirroles():
    drs = db.session.query(DirectoryRole).options(
        selectinload(DirectoryRole.memberUsers),
        selectinload(DirectoryRole.memberGroups),
        selectinload(DirectoryRole.memberServicePrincipals).selectinload(ServicePrincipal.ownerUsers),
        selectinload(DirectoryRole.memberServicePrincipals).selectinload(ServicePrincipal.ownerServicePrincipals)).all()
    return directoryroles_schema.jsonify(drs)

@app.route("/api/tenantdetails", methods=["GET"])
def get_tenantdetails():
    drs = db.session.query(TenantDetail).first()
    return td_schema.jsonify(drs)

@app.route("/api/directorysettings", methods=["GET"])
def get_directorysettings():
    drs = db.session.query(DirectorySetting).first()
    return ds_schema.jsonify(drs)

@app.route("/api/authorizationpolicies", methods=["GET"])
def get_authpolicies():
    drs = db.session.query(AuthorizationPolicy).all()
    return authorizationpolicy_schema.jsonify(drs)

@app.route("/api/stats", methods=["GET"])
def get_stats():
    # pylint: disable=not-callable
    stats = {
        'countUsers': db.session.query(func.count(User.objectId)).scalar(),
        'countGroups': db.session.query(func.count(Group.objectId)).scalar(),
        'countServicePrincipals': db.session.query(func.count(ServicePrincipal.objectId)).scalar(),
        'countApplications': db.session.query(func.count(Application.objectId)).scalar(),
        'countDevices': db.session.query(func.count(Device.objectId)).scalar(),
        'countAdministrativeUnits': db.session.query(func.count(AdministrativeUnit.objectId)).scalar(),
    }
    return jsonify(stats)

# Wrapper that supports paging based on the work of Kevin Tellier (@flashlam)
def query_all_items(request, schema, model, searchfields):
    page = request.args.get('page', type=int)
    rows = request.args.get('limit', type=int)
    search = request.args.get('search', type=str)
    sort_column = request.args.get('sortColumn', type=str)
    sort_order = request.args.get('sortDirection', type=str)

    query = db.session.query(model).options(load_only(*list_columns(model, schema)))

    if search and search != 'undefined':
        # For now only search on the userPrincipalName and displayName fields, others will be added with advanced filtering
        #filter = build_dynamic_filter(user_schema, search)
        filters = []
        for field in searchfields:
            filters.append(getattr(model,field).like(f'%{search}%'))

        query = query.filter(or_(*filters))

    if sort_column and sort_column != 'undefined':
        field = getattr(model, sort_column)
        if hasattr(field, 'type') and isinstance(field.type, JSON):
            # For JSON fields, use the length of the JSON array for sorting
            field = func.json_array_length(cast(field, db.Text))
        elif hasattr(field, 'property') and hasattr(field.property, 'direction'):
            # Handle relationship fields
            field = field.property.direction.mapper.class_.id
        if sort_order and sort_order.lower() == 'desc':
            query = query.order_by(collate(field, "NOCASE").desc())
        else:
            query = query.order_by(collate(field, "NOCASE").asc())

    if page is None and rows is None:
        all_items = query.all()
    else:
        all_items = query.paginate(page=page, per_page=rows)
    result = {
        'items': schema.dump(all_items),
        'count': all_items.total
    }
    return jsonify(result)

def ensure_indexes():
    '''
    Create indexes from the database definition that are missing, for
    databases created by older roadrecon versions. Without them most
    relationship lookups are full table scans.
    '''
    inspector = inspect(db.engine)
    missing = []
    for table in Base.metadata.sorted_tables:
        if not table.indexes or not inspector.has_table(table.name):
            continue
        existing = {index['name'] for index in inspector.get_indexes(table.name)}
        missing += [index for index in table.indexes if index.name not in existing]
    if not missing:
        return
    print(f'Adding {len(missing)} missing indexes to the database to speed up the GUI (only needed once)')
    try:
        with db.engine.begin() as conn:
            for index in missing:
                index.create(conn)
    except SQLAlchemyError as exc:
        print(f'Could not add indexes, the GUI will be slower on large databases: {getattr(exc, "orig", exc)}')

def create_app_test():
    '''
    Create app for unit tests
    '''
    global db
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.getcwd(), 'roadrecon.db')
    if not db:
        db = SQLAlchemy(app)
    return app

def main(args=None):
    global db
    if not args:
        parser = argparse.ArgumentParser(add_help=True, description='ROADrecon GUI', formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument('-d',
                            '--database',
                            action='store',
                            help='Database file. Can be the local database name for SQLite, or an SQLAlchemy compatible URL such as postgresql+psycopg2://dirkjan@/roadtools',
                            default='roadrecon.db')
        parser.add_argument('--debug',
                            action='store_true',
                            help='Enable flask debug')
        parser.add_argument('--profile',
                            action='store_true',
                            help='Enable flask profiler')
        parser.add_argument('--host',
                            type=str,
                            action='store',
                            help='Host IP to bind to (default=127.0.0.1)',
                            default='127.0.0.1')
        parser.add_argument('--port',
                            type=int,
                            action='store',
                            help='HTTP Server port (default=5000)',
                            default=5000)
        args = parser.parse_args()
    if not ':/' in args.database:
        if args.database[0] != '/':
            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.getcwd(), args.database)
        else:
            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + args.database
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = args.database
    db = SQLAlchemy(app)
    with app.app_context():
        ensure_indexes()
    if args.profile:
        from werkzeug.middleware.profiler import ProfilerMiddleware
        app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[5])
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == '__main__':
    main()
