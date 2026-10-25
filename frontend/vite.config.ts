import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({plugins:[react()],server:{proxy:{'/admin-api':'http://localhost:8080','/auth':'http://localhost:8080','/api':'http://localhost:8080','/scim':'http://localhost:8080','/soap':'http://localhost:8080','/graphql':'http://localhost:8080','/oauth':'http://localhost:8080','/banking':'http://localhost:8080','/health':'http://localhost:8080'}}});
