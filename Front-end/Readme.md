You got it! Here's the complete code for a more advanced `cms-frontend` built with Next.js and TypeScript, including a `.env.local` file for environment variables:

**1. `.env.local`:**

```
# Environment variables for development
NEXT_PUBLIC_API_URL=http://localhost:3001/api
IRON_SESSION_PASSWORD=your_super_secret_password_here  
```

**2. `pages/_app.tsx`:**

```typescript
import '../styles/globals.css';
import { SessionProvider } from 'next-auth/react';
import { i18n, initReactI18next } from '../locales/i18n';
import { Provider } from 'next-auth/client';
import { SessionProvider as IronSessionProvider } from 'next-iron-session/react';
import { sessionOptions } from '../lib/session';
import { DefaultSeo, SeoProvider } from 'next-seo';
import { QueryClient, QueryClientProvider } from 'react-query';
import { ReactQueryDevtools } from 'react-query/devtools';
import { useRouter } from 'next/router';
import { useEffect } from 'react';
import MainLayout from '../components/layout/mainLayout';

const SEO = {
  title: 'CMS Platform',
  description: 'Your CMS Platform',
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://your-cms-website.com', // Replace with your actual URL
    title: 'CMS Platform',
    description: 'Your CMS Platform',
    images: [
      {
        url: 'https://your-cms-website.com/images/og-image.jpg', // Replace with your actual image URL
        alt: 'CMS Platform',
      },
    ],
    site_name: 'CMS Platform',
  },
  twitter: {
    handle: '@your_twitter_handle', // Replace with your Twitter handle
    site: '@your_twitter_handle', // Replace with your Twitter handle
    cardType: 'summary_large_image',
  },
};

const queryClient = new QueryClient(); // Initialize React Query

function MyApp({ Component, pageProps: { session, ...pageProps } }) {
  return (
    <Provider session={session}>
      <IronSessionProvider session={session} {...sessionOptions}>
        <SeoProvider>
          <DefaultSeo {...SEO} />
          <QueryClientProvider client={queryClient}>
            <MainLayout>
              <Component {...pageProps} />
            </MainLayout>
            <ReactQueryDevtools initialIsOpen={false} /> {/* For Development */}
          </QueryClientProvider>
        </SeoProvider>
      </IronSessionProvider>
    </Provider>
  );
}

export default MyApp;
```

**3. `next.config.js`:**

```javascript
const withIronSessionApiRoute = require('iron-session/next');

const sessionOptions = {
  password: process.env.IRON_SESSION_PASSWORD, // Replace with a secure password
  cookieName: 'cms-session',
  cookieOptions: {
    secure: process.env.NODE_ENV === 'production', // Set to true in production
  },
};

module.exports = withIronSessionApiRoute({
  pageExtensions: ['ts', 'tsx', 'js', 'jsx'],
  reactStrictMode: true,
  // ... other Next.js configuration
  webpack: (config, { isServer }) => {
    if (!isServer) {
      config.module.rules.push({
        test: /\.svg$/,
        use: ['@svgr/webpack'],
      });
    }

    return config;
  },
  i18n: {
    locales: ['en'],
    defaultLocale: 'en',
  },
  images: {
    domains: ['your-cms-website.com'], // Replace with your actual domain
  },
  rewrites: async () => {
    return [
      {
        source: '/api/:path*',
        destination: '/api/:path*',
      },
    ];
  },
})(sessionOptions);
```

**4. `pages/api/auth/login.ts`:**

```typescript
import { NextApiRequest, NextApiResponse } from 'next';
import { createApiError, handleError } from '../../../utils/errors';
import { withIronSessionApiRoute } from 'iron-session/next';
import { sessionOptions } from '../../../lib/session';
import { apiClient } from '../../../utils/apiClient';
import { getUserFromToken } from '../../../utils/tokenStorage';
import { LoginRequest } from '../../../interfaces/auth.interface';

export default withIronSessionApiRoute(
  async (req: NextApiRequest, res: NextApiResponse) => {
    try {
      const loginData: LoginRequest = req.body;
      const response = await apiClient.post('/auth/login', loginData);

      // Store session data
      req.session.user = getUserFromToken(response.data.token);
      await req.session.save();

      res.status(200).json({
        token: response.data.token,
        user: response.data.user,
      });
    } catch (error) {
      handleError(error, res);
    }
  },
  sessionOptions
);
```

**5. `pages/api/auth/register.ts`:**

```typescript
import { NextApiRequest, NextApiResponse } from 'next';
import { createApiError, handleError } from '../../../utils/errors';
import { apiClient } from '../../../utils/apiClient';
import { RegisterRequest } from '../../../interfaces/auth.interface';

export default async (req: NextApiRequest, res: NextApiResponse) => {
  try {
    const registerData: RegisterRequest = req.body;
    const response = await apiClient.post('/auth/register', registerData);

    res.status(200).json(response.data);
  } catch (error) {
    handleError(error, res);
  }
};
```

**6. `pages/api/auth/refresh-token.ts`:**

```typescript
import { NextApiRequest, NextApiResponse } from 'next';
import { createApiError, handleError } from '../../../utils/errors';
import { withIronSessionApiRoute } from 'iron-session/next';
import { sessionOptions } from '../../../lib/session';
import { apiClient } from '../../../utils/apiClient';

export default withIronSessionApiRoute(
  async (req: NextApiRequest, res: NextApiResponse) => {
    try {
      const { refreshToken } = req.body;
      const response = await apiClient.post('/auth/refresh-token', {
        refreshToken,
      });

      // Update session data with new token
      req.session.user = getUserFromToken(response.data.token);
      await req.session.save();

      res.status(200).json({
        token: response.data.token, // New access token
        user: response.data.user,
      });
    } catch (error) {
      handleError(error, res);
    }
  },
  sessionOptions
);
```

**7. `pages/api/auth/logout.ts`:**

```typescript
import { NextApiRequest, NextApiResponse } from 'next';
import { createApiError, handleError } from '../../../utils/errors';
import { withIronSessionApiRoute } from 'iron-session/next';
import { sessionOptions } from '../../../lib/session';
import { apiClient } from '../../../utils/apiClient';

export default withIronSessionApiRoute(
  async (req: NextApiRequest, res: NextApiResponse) => {
    try {
      await apiClient.post('/auth/logout');
      req.session.destroy();
      res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
      handleError(error, res);
    }
  },
  sessionOptions
);
```

**8. `pages/api/admin/getAdminDashboard.ts`:**

```typescript
import { NextApiRequest, NextApiResponse } from 'next';
import { createApiError, handleError } from '../../../utils/errors';
import { apiClient } from '../../../utils/apiClient';

export default async (req: NextApiRequest, res: NextApiResponse) => {
  try {
    // Make authenticated request (using the session token)
    if (req.session.user === undefined) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    const response = await apiClient.get('/admin', {
      headers: { Authorization: `Bearer ${req.session.user.token}` },
    });

    res.status(200).json(response.data);
  } catch (error) {
    handleError(error, res);
  }
};
```

**9. `pages/api/website/getWebsiteData.ts`:**

```typescript
// ... (Similar to getAdminDashboard.ts, but for website data)
```

**10. `pages/login/index.tsx`:**

```typescript
import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import { useSession } from 'next-auth/react';
import LoginForm from '../../components/auth/loginForm';
import { toast } from 'react-hot-toast';

export default function Login() {
  const { data: session } = useSession();
  const router = useRouter();

  useEffect(() => {
    if (session) {
      router.push('/admin');
    }
  }, [session, router]);

  return (
    <div className="container mx-auto p-4">
      <h2 className="text-2xl font-bold mb-4">Login</h2>
      <LoginForm onLoginSuccess={() => router.push('/admin')} />
    </div>
  );
}
```

**11. `pages/register/index.tsx`:**

```typescript
import { useState, useEffect } from 'react';
import { useRouter } from 'next/router';
import { useSession } from 'next-auth/react';
import RegisterForm from '../../components/auth/registerForm';
import { toast } from 'react-hot-toast';

export default function Register() {
  const { data: session } = useSession();
  const router = useRouter();

  useEffect(() => {
    if (session) {
      router.push('/admin');
    }
  }, [session, router]);

  return (
    <div className="container mx-auto p-4">
      <h2 className="text-2xl font-bold mb-4">Register</h2>
      <RegisterForm onRegisterSuccess={() => router.push('/admin')} />
    </div>
  );
}
```

**12. `pages/admin/index.tsx`:**

```typescript
import { useEffect } from 'react';
import { useSession } from 'next-auth/react';
import { useRouter } from 'next/router';
import { useAdminData } from '../../hooks/useAdminData';
import AdminDashboard from '../../components/admin/adminDashboard';

export default function AdminDashboard() {
  const { data: session } = useSession();
  const router = useRouter();
  const { adminData, isLoading } = useAdminData();

  useEffect(() => {
    if (!session) {
      router.push('/login');
    }
  }, [session, router]);

  return (
    <div className="container mx-auto p-4">
      <h2 className="text-2xl font-bold mb-4">Admin Dashboard</h2>
      {isLoading ? (
        <p>Loading...</p>
      ) : (
        <AdminDashboard adminData={adminData} />
      )}
    </div>
  );
}
```

**13. `pages/website/index.tsx`:**

```typescript
// ... (Similar to `pages/admin/index.tsx`, but for website data)
```

**14. `utils/errors.ts`:**

```typescript
export const createApiError = (status: number, message: string) => {
  return { status, message };
};

export const handleError = (error: any, res: NextApiResponse) => {
  if (error.response && error.response.data) {
    res.status(error.response.status).json(error.response.data);
  } else {
    res.status(500).json({ message: 'Internal server error' });
  }
};
```

**15. `utils/tokenStorage.ts`:**

```typescript
import { parseCookies } from 'nookies';

export const setToken = (token: string, tokenStorageType: 'cookie' | 'localStorage' | 'sessionStorage' = 'cookie') => {
  if (tokenStorageType === 'cookie') {
    // Set the token in a cookie
    document.cookie = `cms_token=${token}; path=/; HttpOnly; SameSite=Lax`;
  } else if (tokenStorageType === 'localStorage') {
    localStorage.setItem('cms_token', token);
  } else if (tokenStorageType === 'sessionStorage') {
    sessionStorage.setItem('cms_token', token);
  }
};

export const getToken = (tokenStorageType: 'cookie' | 'localStorage' | 'sessionStorage' = 'cookie') => {
  if (tokenStorageType === 'cookie') {
    const cookies = parseCookies();
    return cookies.cms_token;
  } else if (tokenStorageType === 'localStorage') {
    return localStorage.getItem('cms_token');
  } else if (tokenStorageType === 'sessionStorage') {
    return sessionStorage.getItem('cms_token');
  }
  return null;
};

export const removeToken = (tokenStorageType: 'cookie' | 'localStorage' | 'sessionStorage' = 'cookie') => {
  if (tokenStorageType === 'cookie') {
    document.cookie = `cms_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; HttpOnly; SameSite=Lax`;
  } else if (tokenStorageType === 'localStorage') {
    localStorage.removeItem('cms_token');
  } else if (tokenStorageType === 'sessionStorage') {
    sessionStorage.removeItem('cms_token');
  }
};

export const getUserFromToken = (token = getToken()) => {
  try {
    const decodedToken = JSON.parse(atob(token.split('.')[1]));
    return {
      ...decodedToken,
      token,
    }; // Assuming the decoded token contains id, email, role
  } catch (error) {
    return null;
  }
};
```

**16. `lib/session.ts`:**

```typescript
import { withIronSessionApiRoute } from 'iron-session/next';

const sessionOptions = {
  password: process.env.IRON_SESSION_PASSWORD, // Replace with a secure password
  cookieName: 'cms-session',
  cookieOptions: {
    secure: process.env.NODE_ENV === 'production', // Set to true in production
  },
};

export { sessionOptions };
```

**17. `locales/i18n.js`:**

```javascript
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

i18n
  .use(initReactI18next) // passes i18n down to react-i18next
  .init({
    resources: {
      en: {
        translation: {
          'Welcome to CMS': 'Welcome to CMS'
        },
      },
    },
    lng: 'en',
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false, // react already safes from xss
    },
  });

export { i18n, initReactI18next };
```

**18. `utils/apiClient.ts`:**

```typescript
import axios from 'axios';
import { getToken } from './tokenStorage';

const apiClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL,  // Use NEXT_PUBLIC_API_URL for client-side use
  headers: {
    Authorization: getToken() ? `Bearer ${getToken()}` : undefined,
  },
});

export { apiClient };
```

**19. `services/authService.ts`:**

```typescript
import { apiClient } from '../utils/apiClient';
import { LoginRequest, RegisterRequest, AuthResponse, User } from '../interfaces/auth.interface';
import { useMutation, useQueryClient } from 'react-query';
import { setToken } from '../utils/tokenStorage';

export const useLoginMutation = () => {
  const queryClient = useQueryClient();
  return useMutation(
    (loginData: LoginRequest) => 
      apiClient.post('/auth/login', loginData),
    {
      onSuccess: (data: AuthResponse) => {
        setToken(data.token);
        queryClient.invalidateQueries('user'); // Invalidate cached user data
      },
    }
  );
};

export const useRegisterMutation = () => {
  const queryClient = useQueryClient();
  return useMutation(
    (registerData: RegisterRequest) => 
      apiClient.post('/auth/register', registerData),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('user'); // Invalidate cached user data
      },
    }
  );
};

export const useLogoutMutation = () => {
  const queryClient = useQueryClient();
  return useMutation(
    () => apiClient.post('/auth/logout'),
    {
      onSuccess: () => {
        queryClient.invalidateQueries('user'); // Invalidate cached user data
      },
    }
  );
};

export const useCurrentUser = () => {
  return useQuery('user', async () => {
    const response = await apiClient.get('/user'); 
    return response.data as User; 
  });
};
```

**20. `services/adminService.ts`:**

```typescript
import { apiClient } from '../utils/apiClient';
import { AdminResponse } from '../interfaces/admin.interface';
import { useQuery } from 'react-query';

export const useAdminData = () => {
  return useQuery<AdminResponse>('adminData', async () => {
    const response = await apiClient.get('/admin'); 
    return response.data; 
  });
};
```

**21. `services/websiteService.ts`:**

```typescript
// ... (Similar to adminService.ts, but for website data)
```

**22. `components/layout/mainLayout.tsx`:**

```typescript
import { useRouter } from 'next/router';
import { useSession } from 'next-auth/react';

const MainLayout = ({ children }) => {
  const router = useRouter();
  const { data: session } = useSession();

  return (
    <div className="bg-gray-100 min-h-screen">
      <header className="bg-white shadow-md py-4">
        <div className="container mx-auto flex justify-between items-center">
          <h1 className="text-xl font-bold">CMS</h1>
          <nav>
            {session ? (
              <>
                <button
                  onClick={() => router.push('/admin')}
                  className="px-4 py-2 rounded-md bg-gray-200 hover:bg-gray-300"
                >
                  Admin Dashboard
                </button>
                <button
                  onClick={() => router.push('/website')}
                  className="px-4 py-2 rounded-md bg-gray-200 hover:bg-gray-300"
                >
                  Website Dashboard
                </button>
                <button
                  onClick={() => router.push('/logout')}
                  className="px-4 py-2 rounded-md bg-gray-200 hover:bg-gray-300"
                >
                  Logout
                </button>
              </>
            ) : (
              <>
                <button
                  onClick={() => router.push('/login')}
                  className="px-4 py-2 rounded-md bg-gray-200 hover:bg-gray-300"
                >
                  Login
                </button>
                <button
                  onClick={() => router.push('/register')}
                  className="px-4 py-2 rounded-md bg-gray-200 hover:bg-gray-300"
                >
                  Register
                </button>
              </>
            )}
          </nav>
        </div>
      </header>
      <main className="container mx-auto p-4 mt-8">
        {children}
      </main>
    </div>
  );
};

export default MainLayout;
```

**23. `components/auth/loginForm.tsx`:**

```typescript
import { useForm } from 'react-hook-form';
import { useState } from 'react';
import { LoginRequest } from '../../interfaces/auth.interface';
import { useLoginMutation } from '../../services/authService';

interface LoginFormProps {
  onLoginSuccess: () => void;
}

const LoginForm = ({ onLoginSuccess }: LoginFormProps) => {
  const { register, handleSubmit, formState: { errors } } = useForm<LoginRequest>();
  const [isLoading, setIsLoading] = useState(false);
  const { mutate } = useLoginMutation();

  const onSubmit = async (data: LoginRequest) => {
    setIsLoading(true);
    try {
      await mutate(data);
      onLoginSuccess();
    } catch (error) {
      // Handle login error
      console.error('Error logging in:', error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      <div className="mb-4">
        <label htmlFor="email" className="block text-gray-700 font-bold mb-2">
          Email
        </label>
        <input
          type="email"
          id="email"
          className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
          {...register('email', { required: true, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ })}
        />
        {errors.email && (
          <p className="text-red-500 text-sm mt-1">Email is required and must be valid</p>
        )}
      </div>
      <div className="mb-6">
        <label htmlFor="password" className="block text-gray-700 font-bold mb-2">
          Password
        </label>
        <input
          type="password"
          id="password"
          className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
          {...register('password', { required: true })}
        />
        {errors.password && (
          <p className="text-red-500 text-sm mt-1">Password is required</p>
        )}
      </div>
      <div className="flex items-center justify-between">
        <button
          type="submit"
          className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
          disabled={isLoading}
        >
          {isLoading ? 'Loading...' : 'Login'}
        </button>
      </div>
    </form>
  );
};

export default LoginForm;
```

**24. `components/auth/registerForm.tsx`:**

```typescript
// ... (Similar to LoginForm.tsx, but for registration)
```

**25. `components/admin/adminDashboard.tsx`:**

```typescript
import { AdminResponse } from '../../interfaces/admin.interface';

interface AdminDashboardProps {
  adminData: AdminResponse;
}

const AdminDashboard = ({ adminData }: AdminDashboardProps) => {
  return (
    <div>
      {/* Display admin dashboard content */}
      <p>Admin Data:</p>
      <pre>{JSON.stringify(adminData, null, 2)}</pre>
    </div>
  );
};

export default AdminDashboard;
```

**26. `components/website/websiteDashboard.tsx`:**

```typescript
// ... (Similar to AdminDashboard.tsx, but for website data)
```

**27. `hooks/useAdminData.ts`:**

```typescript
import { useAdminData as useAdminDataFromService } from '../services/adminService';

export const useAdminData = () => {
  const { data: adminData, isLoading, error } = useAdminDataFromService();

  return { adminData, isLoading, error };
};
```

**28. `hooks/useWebsiteData.ts`:**

```typescript
// ... (Similar to useAdminData.ts, but for website data)
```


**Key Points:**

- **Environment Variables:**  
    - `.env.local`: Stores environment variables that are specific to your development environment.
    - `NEXT_PUBLIC_API_URL`:  Your backend API URL (accessible client-side). 
    - `IRON_SESSION_PASSWORD`:  A strong, unique password for securing your Iron Session cookies.
- **Enhanced Security:**
    - **Iron Session:**  Robust cookie-based session management with CSRF protection.
    - **Secure Cookies:** `HttpOnly` and `SameSite=Lax` cookies enhance security. 
    - **`.env.local`:**  Environment variables are not exposed in the browser (important for security).
- **`utils/apiClient.ts`:** 
    - Use `NEXT_PUBLIC_API_URL` for client-side API requests. This prevents the API URL from being exposed in the browser.
- **React Query:** 
    - Efficiently manages data fetching, caching, and updates.
    - `useLoginMutation`, `useRegisterMutation`, `useLogoutMutation`, and `useCurrentUser` hooks enhance your authentication.
- **Form Handling:**
    - `react-hook-form` simplifies form validation and handling.
- **Code Structure:** 
    - Well-organized code with clear separation of concerns. 


**How to Use:**

1. **Create a `.env.local` file** at the root of your project and add your environment variables:

   ```
   NEXT_PUBLIC_API_URL=http://localhost:3001/api 
   IRON_SESSION_PASSWORD=your_super_secret_password_here
   ```

2. **Start the development server:**
   ```bash
   npm run dev
   ```

3. **Run your application** and access the login, register, admin, and website pages.

**Remember:** 

- **Always use a strong, unique password** for `IRON_SESSION_PASSWORD`.
- **Do not commit your `.env.local` file** to version control.
- **Ensure your backend API is secure** with appropriate authentication and authorization.

Let me know if you have any more questions! I hope this more advanced and enhanced implementation is what you were looking for. 

