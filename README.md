# My Budget Folders — ready-to-deploy cloud app

## Included
- Create account with name, monthly income, and exactly 6-digit PIN
- No default folders: add your own folders and budget amounts
- Add expenses, history, delete expense (the remaining balance recalculates)
- Edit income and folder budgets; CSV export
- Account code + PIN sign-in across devices
- Server-side SQLite database; PIN is stored as a salted scrypt hash

## Important
This ZIP is the prepared app source, not a published website. A hosted URL cannot be generated until this project is deployed to a hosting account. The app does not use your Gmail login or Google Drive. The server itself stores the budget data. Do not share your account code or PIN.

## Deploy
1. Upload this folder to a private GitHub repository.
2. Create a Node Web Service on a host that supports persistent disks (for example Render).
3. Build command: `npm install`; start command: `npm start`.
4. Attach a persistent disk mounted at `/app/data` and set `DATA_DIR=/app/data`.
5. Open the hosted HTTPS URL on your phone, create your account, and save the generated account code.
6. On another device, use “I already have an account” and enter that account code + the same 6-digit PIN.

Requires Node.js 20+. Never commit the `data/` folder or share account details.
