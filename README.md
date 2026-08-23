# 成大學生會 × 麗文書局教科書預訂

成大學生會與麗文書局合作的教科書預訂網站，前端為靜態頁面，認證與授權使用 Supabase。

## 登入方式

| 身分 | 方式 | 登入後 |
| --- | --- | --- |
| 學生 | gs.ncku.edu.tw Google 帳號 | `selection.html`（首次登入先填系所與年級） |
| 管理員（麗文 / 學生會） | Email + 密碼 | `admin.html` |

學生資格由 Google ID token 的 `hd` claim 在伺服器端驗證，**不是**用 email 結尾判斷，
並且該 token 的 Google `sub` 必須已綁定同一個 Supabase 帳號。
管理員資格來自資料庫的 `admin_users` 記錄，登入成功不等於擁有管理權限。

管理員以**單位**為權限邊界：麗文的管理員只能管理麗文的表單、指派、預訂與稽核紀錄，
學生會亦然；`owner` 與 `editor` 是同一單位內的層級，不是跨單位的權力。

## 頁面

| 檔案 | 用途 |
| --- | --- |
| `index.html` | 登入頁 |
| `onboarding.html` | 系所與年級 |
| `selection.html` | 學生看到指派給自己的表單 |
| `form.html` | 填寫單一表單 |
| `admin.html` | 管理後台（表單、指派、預訂結果、管理員、稽核紀錄） |
| `reset-password.html` | 重設密碼 |

## 專案結構

```
js/                      前端模組（ESM）
  config.js              Supabase URL / anon key / Google client ID
  auth.js                認證與授權查詢
  guard.js               頁面守衛（UX 層，非安全邊界）
  routing.js             純函式路由規則，有單元測試
  recovery.js            重設密碼流程判定（純函式，有單元測試）
supabase/
  migrations/            schema、helper functions、guards、RLS、privileged RPC
  functions/
    verify-ncku-student/ Deno 進入點
    _shared/             ID token 驗證與 handler 邏輯（Node 測試共用）
tests/
  routing / recovery / google-id-token / edge-function   純邏輯測試
  sql-policies           在 PGlite（真的 PostgreSQL）上套用 migration 並驗證政策
  rls                    對真實 Supabase 專案的 RLS 測試
docs/SETUP.md            Supabase 與 Google OAuth 設定步驟
```

## 安全邊界

Row Level Security 才是存取控制。即使使用者自行修改 JavaScript、localStorage、
網址或 API request，資料庫仍只回傳授權範圍內的資料：

- 學生只能讀到 `form_assignments` 指派給自己的表單
- 學生不能寫入 `ncku_verified`、`is_active`（連 column 權限都沒有）
- 學生對 `admin_users` 沒有任何權限
- 停權的管理員立即失去所有管理資料的存取權
- 一個單位的管理員讀不到、也改不了另一個單位的表單與預訂資料
- 管理員只看得到「被指派到自己單位表單」的學生資料，沒有全校名冊
- 停權學生只能由學生會 owner 透過 `set_student_active()` 執行，且會留下稽核紀錄

## 本機預覽

需要透過 HTTP 伺服器開啟（ES module 與 Google 登入不支援 `file://`）：
使用 VS Code 的 Live Server 開啟 `index.html`，並把該 origin 加入
Google OAuth 的 Authorized JavaScript origins。

首次設定請見 [`docs/SETUP.md`](docs/SETUP.md)。

## 測試

```bash
npm install
npm test              # local 模式：不需憑證，但會明講「未驗證線上 RLS」
npm run test:security # security 模式：缺設定、缺 migration、有 skip 或失敗都會 fail
```

`npm test` 也會實際把 migration 跑在 in-process 的 PostgreSQL 上，
所以 SQL 語法與政策行為在沒有 Supabase 專案時也是被執行過的；
但線上授權邊界仍必須用 `npm run test:security` 對 scratch 專案驗證。

## 發布

推送至 GitHub 後由 Netlify 自動發布。`js/config.js` 內的值皆可公開；
service role key 與 Google client secret 絕對不可進入此專案。
