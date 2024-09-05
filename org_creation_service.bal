import ballerina/http;
import ballerina/io;
import ballerina/os;

type IsConfigs readonly & record {|
    string server_url;
    string admin_role_name;
    string app_name;
    string app_consumer_key;
    string app_consumer_secret=os:getEnv("CLIENT_SECRET");
|};

type TokenResponse readonly & record {
    string access_token;
};

type CreateOrganizationResponse readonly & record {
    string id;
    string name;
};

type CreateUserResponse readonly & record {
    string id;
    string userName;
};

type Application readonly & record {
    string id;
    string name;
};

type GetAppIdResponse readonly & record {
    int totalResults;
    Application[] applications;
}; 

type RoleResource readonly & record {
    string id;
    string displayName;
};

type GetRoleIdResponse readonly & record {
    int totalResults;
    RoleResource[] Resources;
}; 

configurable IsConfigs isConfigs = ?;

service / on new http:Listener(8080) {

    resource function get test(http:Caller caller) returns error? {

        io:println("Hello, World!");
        check caller->respond("Hello, World!");
    }

    resource function post organization(http:Caller caller, http:Request req) returns error? {
        
        json requestBody = check req.getJsonPayload();
        string organizationName = check requestBody.organizationName;
        string userName = check requestBody.userName;
        string userEmail = check requestBody.userEmail;
        string userFirstName = check requestBody.userFirstName;
        string userLastName = check requestBody.userLastName;

        http:Client oauthClient = check new (isConfigs.server_url);
        http:Client basicClient = check new (isConfigs.server_url, 
            auth = {
                    username: isConfigs.app_consumer_key,
                    password: isConfigs.app_consumer_secret
                }
            );

        string rootAccessToken = check getRootAccessToken(basicClient);
        string orgId = check createNewOrganization(organizationName, oauthClient, rootAccessToken);
        string orgAccessToken = check switchAccessToken(basicClient, rootAccessToken, orgId);
        string userId = check createNewUser(userName, userEmail, userFirstName, userLastName, oauthClient, orgAccessToken);
        string b2bAppId = check getApplicationId(isConfigs.app_name, oauthClient, orgAccessToken);
        string roleId = check getRoleId(isConfigs.admin_role_name, b2bAppId, oauthClient, orgAccessToken);
        check assignUserToRole(userId, roleId, oauthClient, orgAccessToken);

        // Send the response back to the client
        check caller->respond("B2B Organization " + organizationName + " created successfully" + 
            " with the user " + userName);
    }
}

isolated function getRootAccessToken(http:Client apiClient) returns string|error {

    http:Request tokenRequest = new;
    tokenRequest.addHeader("Content-Type", "application/x-www-form-urlencoded");
    tokenRequest.setPayload("grant_type=client_credentials&scope=internal_org_user_mgt_list internal_org_user_mgt_update internal_org_user_mgt_create internal_org_user_mgt_view internal_org_user_mgt_delete internal_org_role_mgt_update internal_org_role_mgt_view internal_org_application_mgt_view internal_org_application_mgt_update internal_organization_delete internal_organization_create internal_organization_view internal_organization_update");

    TokenResponse tokenResponse = check apiClient->post("/oauth2/token", tokenRequest);
    string accessToken = tokenResponse.access_token;
    io:println("Access Token: " + accessToken);
    return accessToken;
}

isolated function createNewOrganization(string organizationName, http:Client apiClient, string accessToken) returns string|error {

    http:Request createOrgRequest = new;
    createOrgRequest.addHeader("Authorization", "Bearer " + accessToken);
    createOrgRequest.addHeader("Content-Type", "application/json");
    createOrgRequest.setPayload("{\"name\": \"" + organizationName + "\"}");

    CreateOrganizationResponse createOrgResponse = check apiClient->post("/api/server/v1/organizations", createOrgRequest);
    string orgId = createOrgResponse.id;
    string orgName = createOrgResponse.name;
    io:println("Organization Created successfully: " + orgName + " with ID: " + orgId);

    return orgId;
}

isolated function switchAccessToken(http:Client apiClient, string rootAccessToken, string orgId) returns string|error {

    http:Request orgTokenRequest = new;
    orgTokenRequest.addHeader("Content-Type", "application/x-www-form-urlencoded");
    orgTokenRequest.setPayload(
        "grant_type=organization_switch" +
        "&scope=internal_org_role_mgt_view internal_org_role_mgt_update internal_org_user_mgt_create internal_org_user_mgt_list internal_org_application_mgt_view" +
        "&token=" + rootAccessToken +
        "&switching_organization=" + orgId
        );

    TokenResponse orgTokenResponse = check apiClient->post("/oauth2/token", orgTokenRequest);
    string orgAccessToken = orgTokenResponse.access_token;
    io:println("Organization Access Token: " + orgAccessToken);
    return orgAccessToken;
}

isolated function createNewUser(string userName, string userEmail, string userFirstName, string userLastName, http:Client apiClient, string accessToken) returns string|error {

    http:Request createUserRequest = new;
    createUserRequest.addHeader("Authorization", "Bearer " + accessToken);
    createUserRequest.addHeader("Content-Type", "application/json");
    createUserRequest.setPayload("{\n" +
            "    \"emails\": [\n" +
            "        {\n" +
            "            \"primary\": true,\n" +
            "            \"value\": \"" + userEmail + "\"\n" +
            "        }\n" +
            "    ],\n" +
            "    \"name\": {\n" +
            "        \"familyName\": \"" + userLastName + "\",\n" +
            "        \"givenName\": \"" + userFirstName + "\"\n" +
            "    },\n" +
            "    \"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User\": {\n" +
            "        \"askPassword\": \"true\"\n" +
            "    },\n" +
            "    \"userName\": \"" + userName + "\"\n" +
            "}");

    CreateUserResponse createUserResponse = check apiClient->post("/o/scim2/Users", createUserRequest);
    string userId = createUserResponse.id;
    io:println("User Created successfully: " + createUserResponse.userName + " with ID: " + userId);

    return userId;
}

isolated function getApplicationId(string appName, http:Client apiClient, string accessToken) returns string|error {

    string appFilterQuery = "name eq " + appName;
    string appEndpoint = "/o/api/server/v1/applications?filter=" + appFilterQuery;

    map<string|string[]> headers = {"Accept": "application/json", "Authorization": "Bearer " + accessToken};
    GetAppIdResponse getAppIdResponse = check apiClient->get(appEndpoint, headers);

    if (getAppIdResponse.totalResults > 0) {
        string b2bAppId = getAppIdResponse.applications[0].id;
        io:println("Application found with the name: " + getAppIdResponse.applications[0].name + " with ID: " + b2bAppId);
        return b2bAppId;
    } else {
        return error("No application found with the name: " + appName);
    }
}

isolated function getRoleId(string roleName, string appId, http:Client apiClient, string accessToken) returns string|error {

    string roleFilterQuery = "displayName eq " + roleName + " and audience.value eq " + appId;
    string roleEndpoint = "/o/scim2/v2/Roles?filter=" + roleFilterQuery;

    map<string|string[]> headers = {"Accept": "application/json", "Authorization": "Bearer " + accessToken};
    GetRoleIdResponse getRoleIdResponse = check apiClient->get(roleEndpoint, headers);
    
    if (getRoleIdResponse.totalResults > 0) {
        string roleId = getRoleIdResponse.Resources[0].id;
        io:println("Role found with the name: " + getRoleIdResponse.Resources[0].displayName + " with ID: " + roleId);
        return roleId;
    } else {
        return error("No role found with the name: " + roleName + " for the application: " + appId);
    }
}

isolated function assignUserToRole(string userId, string roleId, http:Client apiClient, string accessToken) returns error? {

    http:Request patchRoleRequest = new;
    patchRoleRequest.addHeader("Authorization", "Bearer " + accessToken);
    patchRoleRequest.addHeader("Content-Type", "application/json");
    patchRoleRequest.setPayload("{\n" +
            "            \"Operations\": [\n" +
            "                {\n" +
            "                    \"op\": \"add\",\n" +
            "                    \"path\": \"users\",\n" +
            "                    \"value\": [\n" +
            "                        {\n" +
            "                            \"value\": \"" + userId + "\"\n" +
            "                        }\n" +
            "                    ]\n" +
            "                }\n" +
            "            ]\n" +
            "        }"
            );

    http:Response patchRoleResponse = check apiClient->patch("/o/scim2/v2/Roles/" + roleId, patchRoleRequest);

    if (patchRoleResponse.statusCode == 200) {
        io:println("Role assigned successfully");
    } else {
        return error("Error occurred while assigning the role");
        
    }
}