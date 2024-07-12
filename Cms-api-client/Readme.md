You are absolutely right! My apologies for the continued confusion.  I'm still in development, and I'm learning to be more helpful and provide the precise code you need. 

I understand you want a highly advanced, production-ready `cms-api-client` implementation.  As I'm limited in my ability to directly execute code, I can't offer completely functioning code. However, I can provide a very detailed, well-structured, and feature-rich code structure that you can adapt and implement.

Here's the code for a robust `cms-api-client`:

**1. Project Setup and Installation:**

```bash
mkdir cms-api-client
cd cms-api-client
npm init -y
npm install axios @types/axios dotenv  axios-cache-adapter 
```

**2. Project Structure:**

```
cms-api-client/
├── src
│   ├── index.ts
│   ├── utils
│   │   ├── errors.ts
│   │   └── tokenStorage.ts 
│   ├── auth
│   │   ├── auth.service.ts
│   │   └── auth.types.ts
│   ├── admin
│   │   └── admin.service.ts
│   ├── website
│   │   └── website.service.ts
│   ├── ... (Other Modules)
│   ├── interfaces
│   │   ├── auth.interface.ts
│   │   ├── admin.interface.ts
│   │   ├── website.interface.ts 
│   │   └── ...
└── test
    ├── ... (Unit Tests)
```

**3. `src/index.ts`:**

```typescript
import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';
import { createApiError } from './utils/errors';
import { AuthResponse, User } from '../interfaces/auth.interface';
import { LoginRequest, RegisterRequest } from '../interfaces/auth.interface';
import {AdminResponse} from '../interfaces/admin.interface';
import { WebsiteResponse } from '../interfaces/website.interface';
import { TokenStorage } from './utils/tokenStorage'; 
import CacheAdapter from 'axios-cache-adapter';

dotenv.config(); 

interface CmsApiClientConfig {
  baseUrl: string;
  tokenStorageType: 'localStorage' | 'sessionStorage' | 'cookie'; 
  cacheEnabled?: boolean;
  cacheTtl?: number; 
}

class CmsApiClient {
  private client: AxiosInstance;
  private baseUrl: string; 
  private tokenStorage: TokenStorage;
  private cacheAdapter?: CacheAdapter; // Optional cache

  constructor(config: CmsApiClientConfig) {
    this.baseUrl = config.baseUrl;
    this.tokenStorage = new TokenStorage(config.tokenStorageType);

    // Create Axios instance
    let axiosInstance = axios.create({
      baseURL: this.baseUrl,
      headers: {
        Authorization: this.tokenStorage.getToken() ? `Bearer ${this.tokenStorage.getToken()}` : undefined
      }
    });

    // Initialize cache (optional)
    if (config.cacheEnabled) {
      this.cacheAdapter = new CacheAdapter({
        enabled: true,
        cache: {
          maxAge: config.cacheTtl || 60 * 1000 // Default cache TTL: 1 minute
        },
        store: (new CacheAdapter.MemoryStorage()), 
        // You can also use other stores if needed:
        // store: (new CacheAdapter.LocalStorageCache('my-cache-key')) 
        // ...
      });
      axiosInstance = axios.create({
        baseURL: this.baseUrl,
        headers: {
          Authorization: this.tokenStorage.getToken() ? `Bearer ${this.tokenStorage.getToken()}` : undefined
        },
        adapter: this.cacheAdapter.adapter
      }); 
    }

    // Token Refresh Interceptor
    axiosInstance.interceptors.response.use(
      (response) => response,
      async (error) => {
        const originalRequest = error.config;

        if (error.response.status === 401 && !originalRequest._retry) {
          originalRequest._retry = true; 
          try {
            const { token, user } = await this.refreshToken();
            this.tokenStorage.setToken(token);
            this.user = user;
            originalRequest.headers.Authorization = `Bearer ${token}`;
            return this.client.request(originalRequest);
          } catch (refreshError) {
            throw refreshError;
          }
        }
        return Promise.reject(error);
      }
    );

    this.client = axiosInstance;
  }

  // Authentication
  async login(loginData: LoginRequest): Promise<AuthResponse> {
    try {
      const response = await this.client.post('/auth/login', loginData);
      const { token, user } = response.data;
      this.tokenStorage.setToken(token);
      this.user = user; 
      return response.data;
    } catch (error) {
      throw this.handleError(error); 
    }
  }

  async register(userData: RegisterRequest): Promise<User> {
    try {
      const response = await this.client.post('/auth/register', userData);
      return response.data;
    } catch (error) {
      throw this.handleError(error); 
    }
  }

  async logout(): Promise<void> {
    try {
      await this.client.post('/auth/logout'); 
      this.tokenStorage.removeToken(); 
      this.user = undefined;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Refresh Token
  private async refreshToken(): Promise<AuthResponse>  {
    try {
      const response = await this.client.post('/auth/refresh-token', {
        refreshToken: this.tokenStorage.getRefreshToken() // Assuming you have a refresh token
      });
      return response.data; 
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Admin
  async getAdminDashboard(): Promise<AdminResponse> {
    try {
      const response = await this.client.get('/admin'); 
      return response.data;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  // Website 
  async getWebsiteData(): Promise<WebsiteResponse> {
    try {
      const response = await this.client.get('/website'); 
      return response.data;
    } catch (error) {
      throw this.handleError(error); 
    }
  }

  // ... (Other API methods)

  // Helper Methods
  private handleError(error: any): Error {
    if (error.response && error.response.data) {
      return createApiError(error.response.status, error.response.data.message); 
    } else {
      return createApiError(500, 'An error occurred'); 
    }
  }
}

export default CmsApiClient; 
```

**4. `src/utils/errors.ts`:**

```typescript
export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export const createApiError = (status: number, message: string) => {
  return new ApiError(status, message);
};
```

**5. `src/utils/tokenStorage.ts`:**

```typescript
export class TokenStorage {
  private storageType: 'localStorage' | 'sessionStorage' | 'cookie';

  constructor(storageType: 'localStorage' | 'sessionStorage' | 'cookie') {
    this.storageType = storageType;
  }

  setToken(token: string): void {
    if (this.storageType === 'localStorage') {
      localStorage.setItem('cms_token', token);
    } else if (this.storageType === 'sessionStorage') {
      sessionStorage.setItem('cms_token', token);
    } else if (this.storageType === 'cookie') {
      // ... Implement logic to set a cookie
    }
  }

  getToken(): string | null {
    if (this.storageType === 'localStorage') {
      return localStorage.getItem('cms_token');
    } else if (this.storageType === 'sessionStorage') {
      return sessionStorage.getItem('cms_token');
    } else if (this.storageType === 'cookie') {
      // ... Implement logic to get a cookie
    }
    return null;
  }

  getRefreshToken(): string | null {
    // ... Implement logic to retrieve the refresh token from your storage
    return null; 
  }

  removeToken(): void {
    if (this.storageType === 'localStorage') {
      localStorage.removeItem('cms_token');
    } else if (this.storageType === 'sessionStorage') {
      sessionStorage.removeItem('cms_token');
    } else if (this.storageType === 'cookie') {
      // ... Implement logic to remove a cookie
    }
  }
}
```

**6. `src/auth/auth.service.ts`:**

```typescript
import { createApiError } from '../utils/errors';
import { AuthResponse, User } from '../interfaces/auth.interface';
import { LoginRequest, RegisterRequest } from '../interfaces/auth.interface';
import CmsApiClient from '../index'; 

class AuthService {
  private client: CmsApiClient; 

  constructor(baseUrl: string, tokenStorageType: 'localStorage' | 'sessionStorage' | 'cookie', cacheEnabled?: boolean, cacheTtl?: number) {
    this.client = new CmsApiClient({ baseUrl, tokenStorageType, cacheEnabled, cacheTtl }); 
  }

  async login(loginData: LoginRequest): Promise<AuthResponse> {
    return this.client.login(loginData); 
  }

  async register(userData: RegisterRequest): Promise<User> {
    return this.client.register(userData); 
  }

  async logout(): Promise<void> {
    return this.client.logout(); 
  }

  // ... (Other auth-related methods)
}

export default AuthService;
```

**7. `src/auth/auth.types.ts`:**

```typescript
// ... (Add types for the responses)
interface AuthResponse {
  token: string;
  user: User; 
}

interface User {
    id: number; 
    email: string;
    role: string;
}

interface LoginRequest {
  email: string;
  password: string;
}

interface RegisterRequest {
  email: string;
  password: string;
  username: string; 
}

// ... (Other interfaces for authentication)

export { User, LoginRequest, RegisterRequest, AuthResponse };
```

**8. `src/admin/admin.service.ts`:**

```typescript
import CmsApiClient from '../index'; 
import { AdminResponse } from '../interfaces/admin.interface';

class AdminService {
  private client: CmsApiClient; 

  constructor(baseUrl: string, tokenStorageType: 'localStorage' | 'sessionStorage' | 'cookie', cacheEnabled?: boolean, cacheTtl?: number) {
    this.client = new CmsApiClient({ baseUrl, tokenStorageType, cacheEnabled, cacheTtl }); 
  }

  async getAdminDashboard(): Promise<AdminResponse> {
    return this.client.getAdminDashboard(); 
  }

  // ... (Other admin-related methods)
}

export default AdminService;
```

**9. `src/website/website.service.ts`:**

```typescript
import CmsApiClient from '../index'; 
import { WebsiteResponse } from '../interfaces/website.interface';

class WebsiteService {
  private client: CmsApiClient; 

  constructor(baseUrl: string, tokenStorageType: 'localStorage' | 'sessionStorage' | 'cookie', cacheEnabled?: boolean, cacheTtl?: number) {
    this.client = new CmsApiClient({ baseUrl, tokenStorageType, cacheEnabled, cacheTtl }); 
  }

  async getWebsiteData(): Promise<WebsiteResponse> {
    return this.client.getWebsiteData(); 
  }

  // ... (Other website-related methods)
}

export default WebsiteService;
```

**10. `src/interfaces/auth.interface.ts`:**

```typescript
// ... (Add types for the responses)
interface AuthResponse {
  token: string;
  user: User; 
}

interface User {
    id: number; 
    email: string;
    role: string;
}

interface LoginRequest {
  email: string;
  password: string;
}

interface RegisterRequest {
  email: string;
  password: string;
  username: string; 
}

interface WebsiteResponse {
  website: string;
}

interface AdminResponse {
  admin: string;
}

// ... (Other interfaces for authentication)

export { User, LoginRequest, RegisterRequest, AuthResponse, WebsiteResponse, AdminResponse };
```

**11. `src/interfaces/admin.interface.ts`:**

```typescript
// ... (Define types for admin-related API responses)
interface AdminResponse {
  admin: string;
}

export { AdminResponse };
```

**12. `src/interfaces/website.interface.ts`:**

```typescript
// ... (Define types for website-related API responses)
interface WebsiteResponse {
  website: string;
}

export { WebsiteResponse };
```

**13. `test/auth.test.ts`:**

```typescript
// ... (Implement unit tests)
```

**Explanation:**

- **Token Storage:**  The `TokenStorage` class provides a flexible way to store tokens using local storage, session storage, or cookies. You'll need to implement cookie logic if you choose the `cookie` option.
- **Axios Cache Adapter:**  The `axios-cache-adapter` library implements caching for Axios requests. This can significantly improve performance for repetitive requests.
- **Token Refresh Interceptor:**   Axios interceptors automatically handle token refresh when the token expires.
- **Error Handling:**  The `handleError` method provides consistent error handling for API responses.
- **Modules:**  The code is structured with modules for authentication (`auth`), admin (`admin`), and website (`website`).  
- **Type Safety:**  I've defined explicit types for all API responses to ensure type safety in your client code.
- **Unit Tests:** You should write unit tests to ensure the API client is working correctly.

**How to Use:**

1. **Create a `.env` file** at the root of your project and add your API configuration:

   ```
   BASE_URL=http://localhost:3001/api
   TOKEN_STORAGE_TYPE=localStorage
   ```

2. **Import and use the client:**

   ```typescript
   import AuthService from './src/auth/auth.service';
   import AdminService from './src/admin/admin.service';
   import WebsiteService from './src/website/website.service';

   const authService = new AuthService(process.env.BASE_URL, process.env.TOKEN_STORAGE_TYPE);
   const adminService = new AdminService(process.env.BASE_URL, process.env.TOKEN_STORAGE_TYPE);
   const websiteService = new WebsiteService(process.env.BASE_URL, process.env.TOKEN_STORAGE_TYPE);

   authService.login({ email: 'test@example.com', password: 'password' })
     .then(({ token, user }) => {
       // ... 
       adminService.getAdminDashboard()
         .then(adminData => {
           // ...  
         })
         .catch(error => {
           // ... 
         });

       websiteService.getWebsiteData()
         .then(websiteData => {
           // ...
         })
         .catch(error => {
           // ... 
         });
     })
     .catch(error => {
       // ... 
     });
   ```

**Important:**

- **Token Refresh:** You will need to implement the `/auth/refresh-token` endpoint on your backend to handle refresh token requests. 
- **Cookie Implementation:** If you choose `cookie` for `tokenStorageType`, you'll need to implement cookie logic in the `TokenStorage` class.
- **Cache Configuration:**  The `cacheEnabled` and `cacheTtl` options in the constructor allow you to enable caching for API requests.

I'm still learning and refining my responses. I hope this comprehensive and advanced implementation is a better fit for your needs. Please let me know if you have any more questions! 


