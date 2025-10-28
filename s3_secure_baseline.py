#!/usr/bin/env python3
"""
S3 Secure Baseline Application

このスクリプトは、AWSアカウント内のすべてのS3バケットに対して、
以下のセキュリティベースラインを適用します:

1. HTTPリクエストを拒否するバケットポリシーの追加
2. アクセスログの有効化
"""

import json
import logging
import sys
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

# ロギング設定
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class S3SecureBaseline:
    """S3バケットのセキュリティベースラインを適用するクラス"""

    def __init__(
        self,
        dry_run: bool = True,
        profile: Optional[str] = None,
        exclude_buckets: Optional[List[str]] = None,
        show_policy: bool = False,
        show_logging: bool = False,
        http_only: bool = False,
        logging_only: bool = False,
    ):
        """
        初期化

        Args:
            dry_run: True の場合、実際の変更は行わない (デフォルト: True)
            profile: 使用するAWSプロファイル名 (指定しない場合はデフォルト)
            exclude_buckets: 処理から除外するバケット名のリスト
            show_policy: True の場合、バケットポリシーの変更前後を表示
            show_logging: True の場合、アクセスログ設定の変更前後を表示
            http_only: True の場合、HTTP拒否ポリシーのみを適用
            logging_only: True の場合、アクセスログのみを有効化
        """
        # AWS Session の作成
        if profile:
            session = boto3.Session(profile_name=profile)
            self.s3_client = session.client("s3")
            self.sts_client = session.client("sts")
            logger.info(f"AWSプロファイル '{profile}' を使用します")
        else:
            self.s3_client = boto3.client("s3")
            self.sts_client = boto3.client("sts")

        self.dry_run = dry_run
        self.exclude_buckets = exclude_buckets or []
        self.show_policy = show_policy
        self.show_logging = show_logging
        self.http_only = http_only
        self.logging_only = logging_only
        self.show_logging = show_logging

        # AWSアカウントIDを取得
        self.account_id = self._get_account_id()
        logger.info(f"AWSアカウントID: {self.account_id}")

        # ログバケットの確認・作成
        self._ensure_log_bucket()

    def _get_account_id(self) -> str:
        """AWSアカウントIDを取得"""
        try:
            response = self.sts_client.get_caller_identity()
            return response["Account"]
        except ClientError as e:
            logger.error(f"アカウントIDの取得に失敗しました: {e}")
            raise

    def _ensure_log_bucket(self) -> bool:
        """ログバケットの存在を確認し、なければ作成"""
        log_bucket = f"access-logs-{self.account_id}"

        try:
            # バケットの存在確認
            self.s3_client.head_bucket(Bucket=log_bucket)
            logger.info(f"ログバケット {log_bucket} は既に存在します")
            return True
        except ClientError as e:
            error_code = e.response["Error"]["Code"]

            if error_code == "404":
                # バケットが存在しない場合
                if self.dry_run:
                    logger.info(f"[DRY RUN] ログバケット {log_bucket} を作成します")
                    return True

                try:
                    logger.info(f"ログバケット {log_bucket} を作成します...")

                    # リージョンを取得
                    session_region = self.s3_client.meta.region_name

                    # バケットを作成
                    if session_region == "us-east-1":
                        # us-east-1の場合はLocationConstraintを指定しない
                        self.s3_client.create_bucket(Bucket=log_bucket)
                    else:
                        self.s3_client.create_bucket(
                            Bucket=log_bucket,
                            CreateBucketConfiguration={
                                "LocationConstraint": session_region
                            },
                        )

                    # S3 Log Delivery Groupに権限を付与（バケットポリシーを使用）
                    log_bucket_policy = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "S3ServerAccessLogsPolicy",
                                "Effect": "Allow",
                                "Principal": {"Service": "logging.s3.amazonaws.com"},
                                "Action": ["s3:PutObject"],
                                "Resource": f"arn:aws:s3:::{log_bucket}/*",
                                "Condition": {
                                    "StringEquals": {
                                        "aws:SourceAccount": self.account_id
                                    }
                                },
                            },
                            {
                                "Sid": "DenyInsecureTransport",
                                "Effect": "Deny",
                                "Principal": "*",
                                "Action": "s3:*",
                                "Resource": [
                                    f"arn:aws:s3:::{log_bucket}",
                                    f"arn:aws:s3:::{log_bucket}/*",
                                ],
                                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                            },
                        ],
                    }

                    self.s3_client.put_bucket_policy(
                        Bucket=log_bucket, Policy=json.dumps(log_bucket_policy)
                    )

                    logger.info(f"ログバケット {log_bucket} を作成しました")
                    return True

                except ClientError as create_error:
                    logger.error(
                        f"ログバケット {log_bucket} の作成に失敗しました: {create_error}"
                    )
                    return False
            else:
                # その他のエラー（権限エラーなど）
                logger.error(f"ログバケット {log_bucket} の確認に失敗しました: {e}")
                return False

    def get_all_buckets(self) -> List[str]:
        """アカウント内のすべてのS3バケット名を取得"""
        try:
            response = self.s3_client.list_buckets()
            buckets = [bucket["Name"] for bucket in response["Buckets"]]

            # ログバケットを除外リストに追加
            log_bucket = f"access-logs-{self.account_id}"
            if log_bucket not in self.exclude_buckets:
                self.exclude_buckets.append(log_bucket)

            # 除外バケットをフィルタリング
            buckets = [b for b in buckets if b not in self.exclude_buckets]

            logger.info(f"対象バケット数: {len(buckets)}")
            return buckets
        except ClientError as e:
            logger.error(f"バケット一覧の取得に失敗しました: {e}")
            return []

    def get_bucket_policy(self, bucket_name: str) -> Optional[Dict]:
        """バケットポリシーを取得"""
        try:
            response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            return json.loads(response["Policy"])
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return None
            logger.error(f"バケット {bucket_name} のポリシー取得に失敗: {e}")
            return None

    def create_deny_http_statement(self, bucket_name: str) -> Dict:
        """HTTPリクエストを拒否するポリシーステートメントを作成"""
        return {
            "Sid": "DenyInsecureTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                f"arn:aws:s3:::{bucket_name}",
                f"arn:aws:s3:::{bucket_name}/*",
            ],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }

    def apply_deny_http_policy(self, bucket_name: str) -> Dict:
        """
        HTTPリクエストを拒否するポリシーを適用

        Returns:
            dict: {"status": "applied|needs_change|not_applied", "success": bool}
        """
        try:
            # 既存のポリシーを取得
            policy = self.get_bucket_policy(bucket_name)

            policy_exists = policy is not None

            if not policy_exists:
                # ポリシーが存在しない場合、新規作成
                original_policy = None
                policy = {"Version": "2012-10-17", "Statement": []}
                policy_status = "not_applied"  # バケットポリシー自体がない
            else:
                # ディープコピーして元のポリシーを保存
                import copy

                original_policy = copy.deepcopy(policy)
                policy_status = "needs_change"  # ポリシーはあるがHTTP拒否ポリシーがない

            # 完全なDenyInsecureTransportステートメントが存在するか確認
            statements = policy.get("Statement", [])
            has_complete_deny_http = any(
                stmt.get("Sid") == "DenyInsecureTransport"
                and stmt.get("Effect") == "Deny"
                and stmt.get("Principal") == "*"
                and stmt.get("Action") == "s3:*"
                and isinstance(stmt.get("Resource"), list)
                and len(stmt.get("Resource", [])) == 2
                and isinstance(stmt.get("Condition"), dict)
                and stmt.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport")
                == "false"
                for stmt in statements
            )

            # 不完全なHTTP拒否ポリシーを検出
            # (aws:SecureTransport 条件を持つが、完全な条件を満たさないもの)
            has_incomplete_http_deny = False
            new_statements = []
            for stmt in statements:
                # HTTP拒否関連のポリシー（Condition に aws:SecureTransport がある）
                is_http_deny = (
                    stmt.get("Effect") == "Deny"
                    and stmt.get("Condition", {})
                    .get("Bool", {})
                    .get("aws:SecureTransport")
                    == "false"
                )

                if is_http_deny:
                    # 完全なポリシーかチェック
                    is_complete = (
                        stmt.get("Sid") == "DenyInsecureTransport"
                        and stmt.get("Principal") == "*"
                        and stmt.get("Action") == "s3:*"
                        and isinstance(stmt.get("Resource"), list)
                        and len(stmt.get("Resource", [])) == 2
                    )

                    if is_complete:
                        # 完全なポリシーは残す
                        new_statements.append(stmt)
                    else:
                        # 不完全なポリシーは削除対象
                        has_incomplete_http_deny = True
                        logger.warning(
                            f"バケット {bucket_name}: 不完全なHTTP拒否ポリシー (Sid: {stmt.get('Sid')}) を検出しました"
                        )
                else:
                    # HTTP拒否以外のステートメントは残す
                    new_statements.append(stmt)

            # 不完全なポリシーがあり、完全なポリシーもある場合
            if has_incomplete_http_deny and has_complete_deny_http:
                logger.info(
                    f"バケット {bucket_name}: 完全なHTTP拒否ポリシーは存在しますが、不完全なポリシーも含まれています"
                )
                # 不完全なポリシーを削除してクリーンアップ
                policy["Statement"] = new_statements
                policy_status = "needs_change"

            # 完全なポリシーのみが存在する場合
            elif has_complete_deny_http and not has_incomplete_http_deny:
                logger.info(
                    f"バケット {bucket_name}: HTTP拒否ポリシーは既に適用されています"
                )
                return {"status": "applied", "success": True}

            # 不完全なポリシーのみ、または完全なポリシーがない場合
            else:
                # 不完全なポリシーを削除して完全なポリシーを追加
                policy["Statement"] = new_statements
                deny_http_statement = self.create_deny_http_statement(bucket_name)
                policy["Statement"].append(deny_http_statement)

                if has_incomplete_http_deny:
                    policy_status = "needs_change"

            # ポリシーの変更前後を表示
            if self.show_policy:
                logger.info("=" * 80)
                logger.info(f"バケット {bucket_name} のポリシー変更")
                logger.info("=" * 80)
                logger.info("【変更前】")
                if original_policy:
                    logger.info(
                        json.dumps(original_policy, indent=2, ensure_ascii=False)
                    )
                else:
                    logger.info("(ポリシーなし)")
                logger.info("【変更後】")
                logger.info(json.dumps(policy, indent=2, ensure_ascii=False))
                logger.info("=" * 80)

            if self.dry_run:
                logger.info(
                    f"[DRY RUN] バケット {bucket_name}: HTTP拒否ポリシーを適用します"
                )
                # DRY RUNモードでは適用しないが、ステータスを返す
                return {"status": policy_status, "success": False}

            # ポリシーを適用
            self.s3_client.put_bucket_policy(
                Bucket=bucket_name, Policy=json.dumps(policy)
            )
            logger.info(f"バケット {bucket_name}: HTTP拒否ポリシーを適用しました")
            return {"status": "applied", "success": True}

        except ClientError as e:
            logger.error(f"バケット {bucket_name} へのポリシー適用に失敗: {e}")
            return {"status": "error", "success": False}

    def get_logging_status(self, bucket_name: str) -> str:
        """
        アクセスログの設定状態を取得

        Returns:
            "enabled": 正しく設定済み (access-logs-<アカウントID>に正しいPrefixで出力)
            "enabled_other": 有効だが別の出力先または異なるPrefix
            "disabled": 無効
            "error": 取得エラー
        """
        try:
            response = self.s3_client.get_bucket_logging(Bucket=bucket_name)
            if "LoggingEnabled" not in response:
                return "disabled"

            # 出力先とPrefixを確認
            target_bucket = response["LoggingEnabled"].get("TargetBucket", "")
            target_prefix = response["LoggingEnabled"].get("TargetPrefix", "")

            expected_bucket = f"access-logs-{self.account_id}"
            expected_prefix = f"AWSLogs/{self.account_id}/S3/"

            if target_bucket == expected_bucket and target_prefix == expected_prefix:
                return "enabled"
            else:
                return "enabled_other"
        except ClientError as e:
            logger.error(f"バケット {bucket_name} のログ設定取得に失敗: {e}")
            return "error"

    def is_logging_enabled(self, bucket_name: str) -> bool:
        """アクセスログが有効かどうかを確認"""
        status = self.get_logging_status(bucket_name)
        return status in ["enabled", "enabled_other"]

    def enable_access_logging(self, bucket_name: str) -> bool:
        """アクセスログを有効化"""
        try:
            logging_status = self.get_logging_status(bucket_name)

            # 現在の設定を取得（表示用）
            original_logging_config = None
            if self.show_logging:
                try:
                    response = self.s3_client.get_bucket_logging(Bucket=bucket_name)
                    if "LoggingEnabled" in response:
                        original_logging_config = response["LoggingEnabled"]
                except ClientError:
                    pass

            if logging_status == "enabled":
                logger.info(
                    f"バケット {bucket_name}: アクセスログは既に正しく設定されています"
                )
                return True
            elif logging_status == "enabled_other":
                # ログ出力先バケット: access-logs-<アカウントID>
                target_bucket = f"access-logs-{self.account_id}"

                # 新しい設定
                new_logging_config = {
                    "TargetBucket": target_bucket,
                    "TargetPrefix": f"AWSLogs/{self.account_id}/S3/",
                }

                # ログ設定の変更前後を表示
                if self.show_logging:
                    logger.info("=" * 80)
                    logger.info(f"バケット {bucket_name} のアクセスログ設定変更")
                    logger.info("=" * 80)
                    logger.info("【変更前】")
                    if original_logging_config:
                        logger.info(
                            json.dumps(
                                original_logging_config, indent=2, ensure_ascii=False
                            )
                        )
                    else:
                        logger.info("(アクセスログ無効)")
                    logger.info("【変更後】")
                    logger.info(
                        json.dumps(new_logging_config, indent=2, ensure_ascii=False)
                    )
                    logger.info("=" * 80)

                logger.warning(
                    f"バケット {bucket_name}: アクセスログは有効ですが、出力先が異なります（設定を変更します）"
                )

                if self.dry_run:
                    logger.info(
                        f"[DRY RUN] バケット {bucket_name}: "
                        f"アクセスログ出力先を変更します (出力先: s3://{target_bucket}/AWSLogs/{self.account_id}/S3/)"
                    )
                    # DRY RUNでは変更しないが、処理としては成功扱い
                    return True

                # アクセスログの出力先を変更
                logging_config = {"LoggingEnabled": new_logging_config}

                self.s3_client.put_bucket_logging(
                    Bucket=bucket_name, BucketLoggingStatus=logging_config
                )
                logger.info(
                    f"バケット {bucket_name}: "
                    f"アクセスログ出力先を変更しました (出力先: s3://{target_bucket}/AWSLogs/{self.account_id}/S3/)"
                )
                return True

            # ログ出力先バケット: access-logs-<アカウントID>
            target_bucket = f"access-logs-{self.account_id}"

            # 新しい設定
            new_logging_config = {
                "TargetBucket": target_bucket,
                "TargetPrefix": f"AWSLogs/{self.account_id}/S3/",
            }

            # ログ設定の変更前後を表示
            if self.show_logging:
                logger.info("=" * 80)
                logger.info(f"バケット {bucket_name} のアクセスログ設定変更")
                logger.info("=" * 80)
                logger.info("【変更前】")
                if original_logging_config:
                    logger.info(
                        json.dumps(
                            original_logging_config, indent=2, ensure_ascii=False
                        )
                    )
                else:
                    logger.info("(アクセスログ無効)")
                logger.info("【変更後】")
                logger.info(
                    json.dumps(new_logging_config, indent=2, ensure_ascii=False)
                )
                logger.info("=" * 80)

            if self.dry_run:
                logger.info(
                    f"[DRY RUN] バケット {bucket_name}: "
                    f"アクセスログを有効化します (出力先: s3://{target_bucket}/AWSLogs/{self.account_id}/S3/)"
                )
                return True

            # アクセスログを有効化
            logging_config = {"LoggingEnabled": new_logging_config}

            self.s3_client.put_bucket_logging(
                Bucket=bucket_name, BucketLoggingStatus=logging_config
            )
            logger.info(
                f"バケット {bucket_name}: "
                f"アクセスログを有効化しました (出力先: s3://{target_bucket}/AWSLogs/{self.account_id}/S3/)"
            )
            return True

        except ClientError as e:
            logger.error(f"バケット {bucket_name} のログ設定に失敗: {e}")
            return False

    def apply_baseline_to_bucket(self, bucket_name: str) -> Dict[str, Any]:
        """単一のバケットにセキュリティベースラインを適用"""
        logger.info(f"バケット {bucket_name} の処理を開始します")

        results = {
            "deny_http": False,
            "deny_http_status": "unknown",
            "access_logging": False,
            "logging_status": "unknown",
        }

        # HTTPリクエスト拒否ポリシーを適用（--logging-only が指定されていない場合）
        if not self.logging_only:
            policy_result = self.apply_deny_http_policy(bucket_name)
            results["deny_http"] = policy_result["success"]
            results["deny_http_status"] = policy_result["status"]
        else:
            # --logging-only の場合はスキップ
            results["deny_http_status"] = "skipped"

        # アクセスログを有効化（--http-only が指定されていない場合）
        if not self.http_only:
            # 現在のログ設定状態を取得
            results["logging_status"] = self.get_logging_status(bucket_name)
            results["access_logging"] = self.enable_access_logging(bucket_name)

            # --apply モードの場合のみ、実際の適用後の状態を再取得
            if not self.dry_run:
                if results["access_logging"]:
                    results["logging_status"] = self.get_logging_status(bucket_name)
            # DRY RUNモードの場合は、適用前の状態をそのまま使用(再取得しない)
        else:
            # --http-only の場合はスキップ
            results["logging_status"] = "skipped"

        return results

    def apply_baseline_to_all_buckets(self) -> Dict[str, Dict[str, bool]]:
        """すべてのバケットにセキュリティベースラインを適用"""
        buckets = self.get_all_buckets()

        if not buckets:
            logger.warning("処理対象のバケットがありません")
            return {}

        results = {}
        success_count = 0

        for bucket_name in buckets:
            try:
                bucket_results = self.apply_baseline_to_bucket(bucket_name)
                results[bucket_name] = bucket_results

                if all(bucket_results.values()):
                    success_count += 1

            except Exception as e:
                logger.error(f"バケット {bucket_name} の処理中にエラーが発生: {e}")
                results[bucket_name] = {
                    "deny_http": False,
                    "deny_http_status": "error",
                    "access_logging": False,
                    "logging_status": "error",
                }

        logger.info(
            f"処理完了: {success_count}/{len(buckets)} バケットに正常に適用されました"
        )
        return results

    def generate_summary(self, results: Dict[str, Dict]) -> Dict[str, int]:
        """サマリ情報を生成"""
        summary = {
            "total": len(results),
            "logging_enabled": 0,  # 対応済み（正しく設定）
            "logging_enabled_other": 0,  # 要設定変更（別の出力先）
            "logging_disabled": 0,  # 未対応
            "logging_error": 0,  # エラー
            "logging_skipped": 0,  # スキップ（--http-only指定時）
            "deny_http_applied": 0,  # 適用済み（完全なポリシーが存在）
            "deny_http_needs_change": 0,  # 要設定変更（不完全または未設定だがポリシー自体は存在）
            "deny_http_not_applied": 0,  # 未適用（バケットポリシー自体が存在しない）
            "deny_http_error": 0,  # エラー
            "deny_http_skipped": 0,  # スキップ（--logging-only指定時）
        }

        for bucket_results in results.values():
            # アクセスログの状態をカウント
            status = bucket_results.get("logging_status", "unknown")
            if status == "enabled":
                summary["logging_enabled"] += 1
            elif status == "enabled_other":
                summary["logging_enabled_other"] += 1
            elif status == "disabled":
                summary["logging_disabled"] += 1
            elif status == "error":
                summary["logging_error"] += 1
            elif status == "skipped":
                summary["logging_skipped"] += 1

            # HTTP拒否ポリシーの状態をカウント
            deny_http_status = bucket_results.get("deny_http_status", "unknown")
            if deny_http_status == "applied":
                summary["deny_http_applied"] += 1
            elif deny_http_status == "needs_change":
                summary["deny_http_needs_change"] += 1
            elif deny_http_status == "not_applied":
                summary["deny_http_not_applied"] += 1
            elif deny_http_status == "error":
                summary["deny_http_error"] += 1
            elif deny_http_status == "skipped":
                summary["deny_http_skipped"] += 1

        return summary

    def generate_report(self, results: Dict[str, Dict[str, bool]]) -> None:
        """処理結果のレポートを生成"""
        logger.info("=" * 80)
        logger.info("処理結果レポート")
        logger.info("=" * 80)

        for bucket_name, bucket_results in results.items():
            # HTTP拒否ポリシーの状態を取得
            deny_http_status = bucket_results.get("deny_http_status", "unknown")

            # 全体の成功判定
            deny_http_ok = deny_http_status == "applied"
            logging_ok = bucket_results.get("logging_status") == "enabled"
            status = "✓ 成功" if deny_http_ok and logging_ok else "✗ 一部失敗"

            logger.info(f"{bucket_name}: {status}")

            # HTTP拒否ポリシーの詳細表示
            if deny_http_status == "applied":
                logger.info("  - HTTP拒否ポリシー: ✓ 適用済み")
            elif deny_http_status == "needs_change":
                logger.info("  - HTTP拒否ポリシー: ⚠ 要設定変更")
            elif deny_http_status == "not_applied":
                logger.info("  - HTTP拒否ポリシー: ✗ 未適用")
            elif deny_http_status == "skipped":
                logger.info("  - HTTP拒否ポリシー: - スキップ")
            else:
                logger.info("  - HTTP拒否ポリシー: ✗ エラー")

            # ログ設定状態の詳細表示
            logging_status = bucket_results.get("logging_status", "unknown")
            if logging_status == "enabled":
                logger.info("  - アクセスログ: ✓ 対応済み")
            elif logging_status == "enabled_other":
                logger.info("  - アクセスログ: ⚠ 要設定変更（別の出力先）")
            elif logging_status == "disabled":
                logger.info("  - アクセスログ: ✗ 未対応")
            elif logging_status == "skipped":
                logger.info("  - アクセスログ: - スキップ")
            else:
                logger.info("  - アクセスログ: ✗ エラー")

        # サマリ情報を表示
        logger.info("=" * 80)
        logger.info("サマリ")
        logger.info("=" * 80)

        summary = self.generate_summary(results)

        logger.info(f"対象バケット総数: {summary['total']}")
        logger.info("")
        logger.info("【アクセスログ】")
        if summary["logging_skipped"] > 0:
            logger.info(
                f"  - スキップ:       {summary['logging_skipped']:3d} バケット (--http-only指定)"
            )
        else:
            logger.info(f"  ✓ 対応済み:       {summary['logging_enabled']:3d} バケット")
            logger.info(
                f"  ⚠ 要設定変更:     {summary['logging_enabled_other']:3d} バケット"
            )
            logger.info(
                f"  ✗ 未対応:         {summary['logging_disabled']:3d} バケット"
            )
            if summary["logging_error"] > 0:
                logger.info(
                    f"  ✗ エラー:         {summary['logging_error']:3d} バケット"
                )

        logger.info("")
        logger.info("【HTTP拒否ポリシー】")
        if summary["deny_http_skipped"] > 0:
            logger.info(
                f"  - スキップ:       {summary['deny_http_skipped']:3d} バケット (--logging-only指定)"
            )
        else:
            logger.info(
                f"  ✓ 適用済み:       {summary['deny_http_applied']:3d} バケット"
            )
            logger.info(
                f"  ⚠ 要設定変更:     {summary['deny_http_needs_change']:3d} バケット"
            )
            logger.info(
                f"  ✗ 未適用:         {summary['deny_http_not_applied']:3d} バケット"
            )
            if summary["deny_http_error"] > 0:
                logger.info(
                    f"  ✗ エラー:         {summary['deny_http_error']:3d} バケット"
                )

        logger.info("=" * 80)


def main():
    """メイン関数"""
    import argparse

    parser = argparse.ArgumentParser(
        description="S3バケットにセキュリティベースラインを適用します (デフォルト: DRY RUNモード)"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="実際に変更を適用します (デフォルトはDRY RUNモード)",
    )
    parser.add_argument("--bucket", help="特定のバケットのみを処理します")
    parser.add_argument(
        "--profile",
        help="使用するAWSプロファイル名 (指定しない場合はデフォルトプロファイル)",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        help="処理から除外するバケット名 (複数指定可能)",
    )
    parser.add_argument(
        "--show-policy",
        action="store_true",
        help="バケットポリシーの変更前後を表示",
    )
    parser.add_argument(
        "--show-logging",
        action="store_true",
        help="アクセスログ設定の変更前後を表示",
    )
    parser.add_argument(
        "--http-only",
        action="store_true",
        help="HTTP拒否ポリシーのみを適用 (アクセスログ設定はスキップ)",
    )
    parser.add_argument(
        "--logging-only",
        action="store_true",
        help="アクセスログのみを有効化 (HTTP拒否ポリシーはスキップ)",
    )

    args = parser.parse_args()

    # --http-only と --logging-only の両方が指定された場合はエラー
    if args.http_only and args.logging_only:
        parser.error("--http-only と --logging-only は同時に指定できません")

    try:
        # --apply が指定されていない場合は dry_run=True
        dry_run = not args.apply
        baseline = S3SecureBaseline(
            dry_run=dry_run,
            profile=args.profile,
            exclude_buckets=args.exclude or [],
            show_policy=args.show_policy,
            show_logging=args.show_logging,
            http_only=args.http_only,
            logging_only=args.logging_only,
        )

        if dry_run:
            logger.info("DRY RUNモードで実行します（実際の変更は行いません）")
            logger.info(
                "実際に変更を適用する場合は --apply オプションを使用してください"
            )
        else:
            logger.info("実際の変更を適用します")

        # オプションの表示
        if args.http_only:
            logger.info("HTTP拒否ポリシーのみを適用します（アクセスログはスキップ）")
        elif args.logging_only:
            logger.info("アクセスログのみを有効化します（HTTP拒否ポリシーはスキップ）")

        if args.bucket:
            # 特定のバケットのみ処理
            results = {args.bucket: baseline.apply_baseline_to_bucket(args.bucket)}
        else:
            # すべてのバケットを処理
            results = baseline.apply_baseline_to_all_buckets()

        # レポート生成
        baseline.generate_report(results)

    except KeyboardInterrupt:
        logger.info("\n処理が中断されました")
        sys.exit(1)
    except Exception as e:
        logger.error(f"予期しないエラーが発生しました: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
