import axios, { AxiosInstance } from "axios";
import {
  TokenResponse,
  MeResponse,
  MessageResponse,
} from "./models";

export class AuthClient {
  private baseUrl: string;
  private client: AxiosInstance;
  private token: string;
  private refreshToken?: string;

  private constructor(baseUrl: string, token: string, refreshToken?: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.token = token;
    this.refreshToken = refreshToken;
    this.client = axios.create({
      baseURL: this.baseUrl,
      headers: {
        Accept: "application/json",
      },
    });
  }

  // Create an AuthClient by logging in with username/password
  static async loginPassword(
    authUrl: string,
    username: string,
    password: string,
    clientId: string = "app"
  ): Promise<AuthClient> {
    const response = await axios.post<TokenResponse>(
      `${authUrl.replace(/\/+$/, "")}/token`,
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

    return new AuthClient(
      authUrl,
      response.data.access_token,
      response.data.refresh_token
    );
  }

  // Exchange the refresh token for a new access token
  async refresh(): Promise<void> {
    if (!this.refreshToken) {
      throw new Error("No refresh token available.");
    }

    const response = await axios.post<TokenResponse>(
      `${this.baseUrl}/token`,
      new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: this.refreshToken,
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
      }
    );

    this.token = response.data.access_token;
    this.refreshToken = response.data.refresh_token;
  }

  // Get /me (user info)
  async me(): Promise<MeResponse> {
    const response = await this.client.get<MeResponse>("/me", {
      headers: {
        Authorization: `Bearer ${this.token}`,
      },
    });
    return response.data;
  }

  // Revoke a token (defaults to self)
  async revoke(token?: string): Promise<MessageResponse> {
    const data = new URLSearchParams({
      token: token ?? this.token,
    });

    const response = await this.client.post<MessageResponse>("/revoke", data, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });

    return response.data;
  }

  // Get the current access token
  getAccessToken(): string {
    return this.token;
  }

  // Get the current refresh token
  getRefreshToken(): string | undefined {
    return this.refreshToken;
  }
}
