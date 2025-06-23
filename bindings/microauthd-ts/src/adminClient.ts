import axios, { AxiosInstance } from "axios";
import {
  UserObject,
  MessageResponse,
  TokenResponse,
  AuditLogResponse,
  PurgeTokensRequest,
  PurgeAuditLogRequest,
  RoleObject,
  PermissionObject,
  ScopeObject,
  ClientObject,
  SessionResponse,
  RefreshTokenResponse,
  TotpQrResponse,
  VerifyTotpRequest,
  TotpQrRequest,
  MeResponse,
} from "./models";

export class AdminClient {
  private baseUrl: string;
  private token: string;
  private client: AxiosInstance;

  constructor(baseUrl: string, adminToken: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.token = adminToken;
    this.client = axios.create({
      baseURL: this.baseUrl,
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${adminToken}`,
      },
    });
  }

  private static handleError(e: any): never {
    if (e.response) throw new Error(`${e.response.status}: ${JSON.stringify(e.response.data)}`);
    throw e;
  }

  static async loginPassword(
    adminUrl: string,
    username: string,
    password: string,
    clientId: string = "madui"
  ): Promise<AdminClient> {
    const response = await axios.post<TokenResponse>(
      `${adminUrl.replace(/\/+$/, "")}/token`,
      new URLSearchParams({
        grant_type: "password",
        username,
        password,
        client_id: clientId,
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
      }
    );

    return new AdminClient(adminUrl, response.data.access_token);
  }
  
  // SYSTEM DIAGNOSTICS

  /** Ping the admin API */
  async ping(): Promise<void> {
    try {
      await this.client.get("/ping");
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  /** Get version metadata */
  async getVersion(): Promise<Record<string, any>> {
    try {
      const res = await this.client.get<Record<string, any>>("/version");
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  // USERS

  async createUser(username: string, password: string, email: string): Promise<UserObject> {
    try {
      const res = await this.client.post<UserObject>("/users", {
        username,
        user_password: password,
        user_email: email,
      });
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async getUser(id: string): Promise<UserObject | null> {
    try {
      const res = await this.client.get<UserObject>(`/users/${id}`);
      return res.data;
    } catch (e: any) {
      if (e.response && e.response.status === 404) return null;
      AdminClient.handleError(e);
    }
  }

  async getUserIdByUsername(username: string): Promise<string | null> {
    try {
      const res = await this.client.get<{ result: string }>(`/users/id-by-name/${encodeURIComponent(username)}`);
      return res.data.result;
    } catch (e: any) {
      if (e.response?.status === 404) return null;
      AdminClient.handleError(e);
    }
  }

  async updateUser(id: string, email?: string, is_active?: boolean): Promise<UserObject> {
    try {
      const payload: any = {};
      if (email !== undefined) payload.email = email;
      if (is_active !== undefined) payload.is_active = is_active;
      const res = await this.client.put<UserObject>(`/users/${id}`, payload);
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async deactivateUser(id: string): Promise<void> {
    try {
      await this.client.post(`/users/deactivate/${id}`);
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async activateUser(id: string): Promise<void> {
    try {
      await this.client.post(`/users/${id}/activate`);
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async resetUserPassword(id: string, newPassword: string): Promise<void> {
    try {
      await this.client.post(`/users/${id}/reset`, { password: newPassword });
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async deleteUser(id: string): Promise<void> {
    try {
      await this.client.delete(`/users/${id}`);
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async listUsers(): Promise<UserObject[]> {
    try {
      const res = await this.client.get<UserObject[]>("/users");
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  // ROLES

  async createRole(name: string, description: string): Promise<RoleObject> {
    try {
      const res = await this.client.post<RoleObject>("/roles", { name, description });
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async updateRole(id: string, description: string): Promise<RoleObject> {
    try {
      const res = await this.client.put<RoleObject>(`/roles/${id}`, { description });
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async getRole(id: string): Promise<RoleObject | null> {
    try {
      const res = await this.client.get<RoleObject>(`/roles/${id}`);
      return res.data;
    } catch (e: any) {
      if (e.response && e.response.status === 404) return null;
      AdminClient.handleError(e);
    }
  }

  async getRoleIdByName(name: string): Promise<string | null> {
    try {
      const res = await this.client.get<{ result: string }>(`/roles/id-by-name/${encodeURIComponent(name)}`);
      return res.data.result;
    } catch (e: any) {
      if (e.response?.status === 404) return null;
      AdminClient.handleError(e);
    }
  }

  async deleteRole(id: string): Promise<void> {
    try {
      await this.client.delete(`/roles/${id}`);
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async listRoles(): Promise<RoleObject[]> {
    try {
      const res = await this.client.get<RoleObject[]>("/roles");
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async assignRoleToUser(userId: string, roleId: string): Promise<void> {
    try {
      await this.client.post("/roles/assign", {
        user_id: userId,
        role_id: roleId,
      });
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async unassignRoleFromUser(userId: string, roleId: string): Promise<void> {
    try {
      await this.client.post("/roles/unassign", {
        user_id: userId,
        role_id: roleId,
      });
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async listRolesForUser(userId: string): Promise<RoleObject[]> {
    try {
      const res = await this.client.get<RoleObject[]>(`/roles/user/${userId}`);
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  // PERMISSIONS

  async createPermission(name: string): Promise<PermissionObject> {
    try {
      const res = await this.client.post<PermissionObject>("/permissions", { name });
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async updatePermission(id: string, name: string): Promise<PermissionObject> {
    try {
      const res = await this.client.put<PermissionObject>(`/permissions/${id}`, { name });
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async getPermission(id: string): Promise<PermissionObject | null> {
    try {
      const res = await this.client.get<PermissionObject>(`/permissions/${id}`);
      return res.data;
    } catch (e: any) {
      if (e.response && e.response.status === 404) return null;
      AdminClient.handleError(e);
    }
  }

  async getPermissionIdByName(name: string): Promise<string | null> {
    try {
      const res = await this.client.get<{ result: string }>(`/permissions/id-by-name/${encodeURIComponent(name)}`);
      return res.data.result;
    } catch (e: any) {
      if (e.response?.status === 404) return null;
      AdminClient.handleError(e);
    }
  }

  async listPermissions(): Promise<PermissionObject[]> {
    try {
      const res = await this.client.get<PermissionObject[]>("/permissions");
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async deletePermission(id: string): Promise<void> {
    try {
      await this.client.delete(`/permissions/${id}`);
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async assignPermissionToRole(roleId: string, permissionId: string): Promise<void> {
    try {
      await this.client.post(`/roles/${roleId}/permissions`, { permission_id: permissionId });
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async removePermissionFromRole(roleId: string, permissionId: string): Promise<void> {
    try {
      await this.client.delete(`/roles/${roleId}/permissions/${permissionId}`);
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async listPermissionsForUser(userId: string): Promise<PermissionObject[]> {
    try {
      const res = await this.client.get<PermissionObject[]>(`/permissions/user/${userId}`);
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  // SCOPES

  async createScope(name: string, description: string): Promise<ScopeObject> {
    try {
      const res = await this.client.post<ScopeObject>("/scopes", { name, description });
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async updateScope(id: string, description: string): Promise<ScopeObject> {
    try {
      const res = await this.client.put<ScopeObject>(`/scopes/${id}`, { description });
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async getScope(id: string): Promise<ScopeObject> {
    try {
      const res = await this.client.get<ScopeObject>(`/scopes/${id}`);
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async getScopeIdByName(name: string): Promise<string | null> {
    try {
      const res = await this.client.get<{ result: string }>(`/scopes/id-by-name/${encodeURIComponent(name)}`);
      return res.data.result;
    } catch (e: any) {
      if (e.response?.status === 404) return null;
      AdminClient.handleError(e);
    }
  }

  async listScopes(): Promise<ScopeObject[]> {
    try {
      const res = await this.client.get<ScopeObject[]>("/scopes");
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async deleteScope(id: string): Promise<void> {
    try {
      await this.client.delete(`/scopes/${id}`);
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async assignScopeToUser(userId: string, scopeId: string): Promise<void> {
    try {
      await this.client.post(`/users/${userId}/scopes`, {
        user_id: userId,
        scope_id: scopeId,
      });
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async removeScopeFromUser(userId: string, scopeId: string): Promise<void> {
    try {
      await this.client.delete(`/users/${userId}/scopes/${scopeId}`);
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async listScopesForUser(userId: string): Promise<ScopeObject[]> {
    try {
      const res = await this.client.get<ScopeObject[]>(`/users/${userId}/scopes`);
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async assignScopeToClient(clientId: string, scopeId: string): Promise<void> {
    try {
      await this.client.post(`/clients/${clientId}/scopes`, {
        client_id: clientId,
        scope_id: scopeId,
      });
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async removeScopeFromClient(clientId: string, scopeId: string): Promise<void> {
    try {
      await this.client.delete(`/clients/${clientId}/scopes/${scopeId}`);
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async listScopesForClient(clientId: string): Promise<ScopeObject[]> {
    try {
      const res = await this.client.get<ScopeObject[]>(`/clients/${clientId}/scopes`);
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  // CLIENTS

  async createClient(clientId: string, secret: string, displayName: string, audience: string): Promise<ClientObject> {
    try {
      const res = await this.client.post<ClientObject>("/clients", {
        client_id: clientId,
        secret,
        display_name: displayName,
        audience,
      });
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async updateClient(id: string, displayName: string, audience: string): Promise<ClientObject> {
    try {
      const res = await this.client.put<ClientObject>(`/clients/${id}`, {
        display_name: displayName,
        audience,
      });
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async getClient(id: string): Promise<ClientObject> {
    try {
      const res = await this.client.get<ClientObject>(`/clients/${id}`);
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async getClientIdByName(clientId: string): Promise<string | null> {
    try {
      const res = await this.client.get<{ result: string }>(`/clients/id-by-name/${encodeURIComponent(clientId)}`);
      return res.data.result;
    } catch (e: any) {
      if (e.response?.status === 404) return null;
      AdminClient.handleError(e);
    }
  }

  async listClients(): Promise<ClientObject[]> {
    try {
      const res = await this.client.get<ClientObject[]>("/clients");
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async deleteClient(id: string): Promise<void> {
    try {
      await this.client.delete(`/clients/${id}`);
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  // AUDIT LOGS

  async listAuditLogs(): Promise<AuditLogResponse[]> {
    try {
      const res = await this.client.get<AuditLogResponse[]>("/audit-logs");
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async getAuditLogById(id: string): Promise<AuditLogResponse> {
    try {
      const res = await this.client.get<AuditLogResponse>(`/audit-logs/${id}`);
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async purgeAuditLogs(req: PurgeAuditLogRequest): Promise<MessageResponse> {
    try {
      const res = await this.client.post<MessageResponse>("/audit-logs/purge", req);
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  // TOTP

  async generateTotp(req: TotpQrRequest): Promise<TotpQrResponse> {
    try {
      const res = await this.client.post<TotpQrResponse>(`/users/${req.user_id}/totp/generate`, req);
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  async verifyTotp(req: VerifyTotpRequest): Promise<boolean> {
    try {
      const res = await this.client.post(`/users/totp/verify`, req);
      return res.status === 200;
    } catch (e: any) {
      if (e.response?.status === 403) return false;
      AdminClient.handleError(e);
    }
  }

  async disableTotp(userId: string): Promise<MessageResponse> {
    try {
      const res = await this.client.post<MessageResponse>(`/users/${userId}/disable-totp`);
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  // INTROSPECTION

  async introspect(token: string): Promise<Record<string, any>> {
    try {
      const res = await this.client.post("/introspect", { token });
      return res.data;
    } catch (e) {
      AdminClient.handleError(e);
    }
  }

  // VERIFY PASSWORD

  async verifyPassword(userId: string, password: string): Promise<boolean> {
    try {
      const res = await this.client.post(`/users/verify-password`, { user_id: userId, password });
      return res.status === 200;
    } catch (e: any) {
      if (e.response?.status === 403) return false;
      AdminClient.handleError(e);
    }
  }
}
