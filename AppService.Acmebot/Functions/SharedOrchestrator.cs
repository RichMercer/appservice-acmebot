using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using AppService.Acmebot.Models;

using DurableTask.TypedProxy;

using Microsoft.Azure.Management.WebSites.Models;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.DurableTask;

namespace AppService.Acmebot.Functions
{
    public class SharedOrchestrator
    {
        [FunctionName(nameof(IssueCertificate))]
        public async Task<Certificate> IssueCertificate([OrchestrationTrigger] IDurableOrchestrationContext context)
        {
            var (site, dnsNames, forceDns01Challenge) = context.GetInput<(Site, string[], bool)>();

            var activity = context.CreateActivityProxy<ISharedActivity>();

            // ワイルドカード、コンテナ、Linux の場合は DNS-01 を利用する
            var isCustomDomain = !dnsNames.Any(x => x.Contains("clubpal.") || x.Contains("entrypal."));
            var useDns01Auth = forceDns01Challenge || dnsNames.Any(x => x.StartsWith("*")) || site.Kind.Contains("container") || site.Kind.Contains("linux");

            // 前提条件をチェック
            if (isCustomDomain)
            {
                // Custom domains don't require the precondition as the Controller will handler the request
            }
            else if (useDns01Auth)
            {
                await activity.Dns01Precondition(dnsNames);
            }
            else
            {
                await activity.Http01Precondition(site);
            }

            // 新しく ACME Order を作成する
            var orderDetails = await activity.Order(dnsNames);

            // 既に確認済みの場合は Challenge をスキップする
            if (orderDetails.Payload.Status != "ready")
            {
                // 複数の Authorizations を処理する
                IReadOnlyList<AcmeChallengeResult> challengeResults;

                // ACME Challenge を実行
                if (isCustomDomain)
                {
                    // TODO: ClubPal function here that will save 
                    challengeResults = await activity.ClubPalAuthorization((site, orderDetails.Payload.Authorizations));

                    await activity.CheckHttpChallenge(challengeResults);
                }
                else if (useDns01Auth)
                {
                    challengeResults = await activity.Dns01Authorization(orderDetails.Payload.Authorizations);

                    // DNS レコードの変更が伝搬するまで 10 秒遅延させる
                    await context.CreateTimer(context.CurrentUtcDateTime.AddSeconds(10), CancellationToken.None);

                    // Azure DNS で正しくレコードが引けるか確認
                    await activity.CheckDnsChallenge(challengeResults);
                }
                else
                {
                    challengeResults = await activity.Http01Authorization((site, orderDetails.Payload.Authorizations));

                    // HTTP で正しくアクセスできるか確認
                    await activity.CheckHttpChallenge(challengeResults);
                }

                // ACME Answer を実行
                await activity.AnswerChallenges(challengeResults);

                // Order のステータスが ready になるまで 60 秒待機
                await activity.CheckIsReady((orderDetails, challengeResults));

                if (isCustomDomain)
                {
                    await activity.CleanupClubPalChallenge(challengeResults);
                }
                else if (useDns01Auth)
                {
                    // 作成した DNS レコードを削除
                    await activity.CleanupDnsChallenge(challengeResults);
                }
            }

            // CSR を作成し Finalize を実行
            var (finalize, rsaParameters) = await activity.FinalizeOrder((dnsNames, orderDetails));

            // Finalize の時点でステータスが valid の時点はスキップ
            if (orderDetails.Payload.Status != "valid")
            {
                // Finalize 後のステータスが valid になるまで 60 秒待機
                await activity.CheckIsValid(orderDetails);
            }

            // 証明書をダウンロードし App Service へアップロード
            var certificate = await activity.UploadCertificate((site, dnsNames[0], forceDns01Challenge, finalize, rsaParameters));

            return certificate;
        }
    }
}
