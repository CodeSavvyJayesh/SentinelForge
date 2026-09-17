# SentinelForge — Frontend

React 19 + TypeScript + Vite. See the root [README](../README.md) for the full project.

```powershell
cd frontend
copy .env.example .env      # sets VITE_API_BASE_URL
npm install
npm run dev                 # http://localhost:5173
```

| Script              | Purpose                                   |
| ------------------- | ----------------------------------------- |
| `npm run dev`       | Dev server with hot reload                |
| `npm run build`     | Type-check (`tsc -b`) then production build |
| `npm run typecheck` | Type-check only                           |
| `npm run lint`      | ESLint (typescript-eslint, react-hooks)   |
| `npm run test`      | Unit tests (Vitest)                       |

## Structure

```
src/
├── config/      env.ts – reads and validates VITE_* variables
├── services/    apiClient.ts (fetch wrapper, error envelope, timeouts), feature services
├── hooks/       React hooks that call services and expose loading/success/error state
├── types/       TypeScript mirrors of backend schemas
├── components/  Reusable presentational components (no API calls)
├── layouts/     App shell
├── pages/       Screens composed from hooks + components
├── utils/       Pure helpers (formatting)
└── styles/      Design tokens and global CSS
```

Rule: components never call `fetch` directly — pages use hooks, hooks use services,
services use the single `apiClient`.
