# S3 Secure Baseline

Amazon S3 バケットに対して、**HTTPリクエスト拒否ポリシー** と **アクセスログの有効化** を一括でチェック・提案・適用するためのツールです。

AWS セキュリティ監査やコンプライアンス要件に対応する運用支援スクリプトです。

## 📌 機能

- 指定したアカウント内の **すべての S3 バケット** に対し、セキュリティベースラインをチェック
- **HTTP拒否ポリシー** を自動的に
  - 存在チェック（完全性の検証）
  - 不完全なポリシーの検出・削除
  - 提案または適用
- **アクセスログ** を自動的に
  - 有効化状態をチェック
  - 出力先とPrefixの正当性を検証
  - 提案または適用
- バケットごとの
  - 現在のポリシー
  - 現在のログ設定
  - 提案（適用後）の内容
  の表示に対応（`--show-policy` / `--show-logging`）
- `--apply` オプションにより一括適用可能
- 既に同等の設定が存在する場合はスキップ
- 既存のバケットポリシーやログルールを壊さずに追記・更新
- ログバケット（`access-logs-<アカウントID>`）の自動作成
- **3段階の状態分類**で設定状況を可視化
  - ✓ 適用済み（完全な設定）
  - ⚠ 要設定変更（不完全または別の出力先）
  - ✗ 未適用（設定なし）

## 🧰 必要環境

- Python 3.8 以上
- AWS CLI 認証済みの環境（`~/.aws/credentials` 等）
- `boto3` ライブラリ

### インストール

```bash
pip install -r requirements.txt
```

または

```bash
pip install boto3
```

## 🚀 使い方

### 1. ドライラン（提案のみ）

```bash
python s3_secure_baseline.py
```

または特定のプロファイルで

```bash
python s3_secure_baseline.py --profile my-aws-profile
```

- 実際には S3 へ変更を加えず、変更が必要なバケットを表示します。

### 2. 実際に設定を適用

```bash
python s3_secure_baseline.py --apply
```

または

```bash
python s3_secure_baseline.py --profile my-aws-profile --apply
```

- HTTP拒否ポリシーが存在しない、または不適切なバケットに対して `DenyInsecureTransport` というポリシーを追加または更新します。
- アクセスログが無効、または別の出力先になっているバケットに対して、標準の出力先（`access-logs-<アカウントID>`）を設定します。

### 3. 特定のバケットのみ処理

```bash
python s3_secure_baseline.py --apply --bucket my-bucket-name
```

### 4. 特定のバケットを除外

```bash
python s3_secure_baseline.py --apply --exclude bucket-to-exclude-1 --exclude bucket-to-exclude-2
```

### 5. 現在と提案の設定を表示する

```bash
python s3_secure_baseline.py --show-policy --show-logging
```

- 現在のバケットポリシーとアクセスログ設定、提案後の内容を JSON 形式で標準出力に表示します。

### 6. HTTP拒否ポリシーのみを適用

```bash
python s3_secure_baseline.py --apply --http-only
```

- アクセスログ設定はスキップし、HTTP拒否ポリシーのみを適用します。

### 7. アクセスログのみを有効化

```bash
python s3_secure_baseline.py --apply --logging-only
```

- HTTP拒否ポリシーはスキップし、アクセスログのみを有効化します。

## 📝 オプション一覧

| オプション | 説明 |
|-----------|------|
| `--apply` | 実際に S3 バケットへ設定を適用する（デフォルトはドライラン） |
| `--profile <name>` | 使用する AWS CLI プロファイル名 |
| `--bucket <name>` | 特定のバケットのみを処理 |
| `--exclude <name>` | 処理から除外するバケット名（複数指定可能） |
| `--show-policy` | バケットポリシーの変更前後を JSON 形式で表示 |
| `--show-logging` | アクセスログ設定の変更前後を JSON 形式で表示 |
| `--http-only` | HTTP拒否ポリシーのみを適用（アクセスログ設定はスキップ） |
| `--logging-only` | アクセスログのみを有効化（HTTP拒否ポリシーはスキップ） |

## 🧭 処理の流れ

1. AWSアカウントIDを取得（`sts:GetCallerIdentity`）
2. ログバケット（`access-logs-<アカウントID>`）の存在確認・必要に応じて自動作成
   - 作成時に **HTTP拒否ポリシー** と **ログ配信権限** を自動設定
   - ログバケット自体は以降の処理対象から **自動的に除外**
3. 対象バケット一覧を取得（`s3:ListAllMyBuckets`）
   - ログバケットは除外済み
   - `--exclude` オプションで指定されたバケットも除外
4. 各バケットに対し以下を実行
   - `GetBucketPolicy` でバケットポリシーを取得
   - HTTP拒否ポリシー（`DenyInsecureTransport`）の完全性をチェック
     - 完全な設定: Sid, Effect, Principal, Action, Resource, Condition すべてが適切
     - 不完全な設定: aws:SecureTransport 条件はあるが Action や Resource が不足
   - `GetBucketLogging` でアクセスログ設定を取得
   - 出力先バケットとPrefixの正当性をチェック
5. 変更が必要な場合、`--apply` オプションがあれば適用
   - `PutBucketPolicy` でポリシーを追加または更新
   - `PutBucketLogging` でアクセスログを有効化
6. 処理結果のサマリを出力

## 🛡️ IAM 必要権限

最小権限ポリシーの例：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketPolicy",
        "s3:PutBucketPolicy",
        "s3:GetBucketLogging",
        "s3:PutBucketLogging",
        "s3:CreateBucket",
        "s3:PutBucketPublicAccessBlock"
      ],
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
```

## 📊 出力例

### ドライラン実行時

```
2025-10-28 10:00:00,123 - INFO - AWSプロファイル 'dev-profile' を使用します
2025-10-28 10:00:00,456 - INFO - AWSアカウントID: 123456789012
2025-10-28 10:00:00,789 - INFO - ログバケット access-logs-123456789012 は既に存在します
2025-10-28 10:00:00,901 - INFO - DRY RUNモードで実行します（実際の変更は行いません）
2025-10-28 10:00:00,902 - INFO - 実際に変更を適用する場合は --apply オプションを使用してください
2025-10-28 10:00:01,234 - INFO - 対象バケット数: 5
2025-10-28 10:00:01,345 - INFO - バケット my-bucket-1 の処理を開始します
2025-10-28 10:00:01,456 - WARNING - バケット my-bucket-1: 不完全なHTTP拒否ポリシー (Sid: DenyHTTP) を検出しました
2025-10-28 10:00:01,567 - INFO - バケット my-bucket-1: 完全なHTTP拒否ポリシーは存在しますが、不完全なポリシーも含まれています
2025-10-28 10:00:01,678 - INFO - [DRY RUN] バケット my-bucket-1: HTTP拒否ポリシーを適用します
2025-10-28 10:00:01,789 - INFO - [DRY RUN] バケット my-bucket-1: アクセスログを有効化します (出力先: s3://access-logs-123456789012/AWSLogs/123456789012/S3/)
...
================================================================================
処理結果レポート
================================================================================
my-bucket-1: ✗ 一部失敗
  - HTTP拒否ポリシー: ⚠ 要設定変更
  - アクセスログ: ✗ 未対応
my-bucket-2: ✓ 成功
  - HTTP拒否ポリシー: ✓ 適用済み
  - アクセスログ: ✓ 対応済み
my-bucket-3: ✗ 一部失敗
  - HTTP拒否ポリシー: ✗ 未適用
  - アクセスログ: ⚠ 要設定変更（別の出力先）
================================================================================
サマリ
================================================================================
対象バケット総数: 5

【アクセスログ】
  ✓ 対応済み:         2 バケット
  ⚠ 要設定変更:       1 バケット
  ✗ 未対応:           2 バケット

【HTTP拒否ポリシー】
  ✓ 適用済み:         2 バケット
  ⚠ 要設定変更:       1 バケット
  ✗ 未適用:           2 バケット
================================================================================
```

## 🔍 セキュリティ対策の詳細

### 1. HTTP拒否ポリシー

完全なHTTP拒否ポリシーの例：

```json
{
  "Sid": "DenyInsecureTransport",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": [
    "arn:aws:s3:::bucket-name",
    "arn:aws:s3:::bucket-name/*"
  ],
  "Condition": {
    "Bool": {
      "aws:SecureTransport": "false"
    }
  }
}
```

**検証項目：**
- `Sid`: `DenyInsecureTransport`
- `Effect`: `Deny`
- `Principal`: `*`（全ユーザー）
- `Action`: `s3:*`（全アクション）
- `Resource`: バケットとオブジェクトの両方（2つのARN）
- `Condition`: `aws:SecureTransport` = `false`

不完全なポリシー（例: `Action` が `s3:GetObject` のみ）は検出され、完全なポリシーに置き換えられます。

### 2. アクセスログ

**標準の設定：**
- **出力先バケット**: `access-logs-<アカウントID>`
- **Prefix**: `AWSLogs/<アカウントID>/S3/`

**自動作成：**
ログバケットが存在しない場合、以下の設定で自動作成されます：
- **HTTP拒否ポリシー（DenyInsecureTransport）** を自動設定
- **S3 ロギングサービスプリンシパル**（`logging.s3.amazonaws.com`）に `PutObject` 権限を付与
- パブリックアクセスブロック有効
- **作成後は処理対象から自動的に除外**（ログの無限ループを防止）

**ログバケットのポリシー例：**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ServerAccessLogsPolicy",
      "Effect": "Allow",
      "Principal": {
        "Service": "logging.s3.amazonaws.com"
      },
      "Action": ["s3:PutObject"],
      "Resource": "arn:aws:s3:::access-logs-123456789012/*",
      "Condition": {
        "StringEquals": {
          "aws:SourceAccount": "123456789012"
        }
      }
    },
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::access-logs-123456789012",
        "arn:aws:s3:::access-logs-123456789012/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

## 🧪 開発メモ

- `put-bucket-policy` は **全ステートメントを置換** するため、このツールでは **既存ポリシーを読み取り → 必要なステートメントを追記/更新 → まとめて再適用** という安全な手順をとっています。
- 既に適切なポリシーや設定があるバケットは何も変更しません。
- `--show-policy` / `--show-logging` を活用することで、事前に提案内容をレビューしてから適用できます。
- 不完全なHTTP拒否ポリシー（`aws:SecureTransport` 条件はあるが `Action` や `Resource` が不足）は自動的に検出・削除され、完全なポリシーに置き換えられます。
- **ログバケット自体は処理対象から自動除外**されるため、以下のメリットがあります：
  - ログの無限ループを防止（ログバケットのログをログバケットに保存しない）
  - `--exclude` でログバケットを明示的に指定する必要がない
  - ログバケットは作成時に既にセキュアな状態で構成済み

**👉 推奨運用：**

1. まず `python s3_secure_baseline.py --show-policy --show-logging` で全体を確認
2. レビュー後に `--apply` で一括反映
3. 新規バケット対応のため、CI や Lambda 定期実行にも組み込み可能
4. 部分適用が必要な場合は `--http-only` または `--logging-only` を活用
5. ログバケット（`access-logs-<アカウントID>`）は自動的に除外されるため、特別な設定は不要

## 🧼 参考情報

- [Amazon S3 セキュリティベストプラクティス](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [S3 バケットポリシーの例](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
- [S3 サーバーアクセスのログ記録](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html)
- [AWS Trusted Advisor — S3 セキュリティチェック](https://docs.aws.amazon.com/awssupport/latest/user/trusted-advisor.html)
