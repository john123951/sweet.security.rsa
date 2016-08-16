using Cn.Ubingo.Security.RSA.Core;
using Cn.Ubingo.Security.RSA.Data;
using System;
using System.IO;
using System.Text;

namespace Cn.Ubingo.Security.RSA.Test
{
    /// <summary>
    /// 陈服建(fochen,j@ubingo.cn)
    /// 2015-01-23
    /// </summary>
    internal class Program
    {
        private static void Main(string[] args)
        {
            //ReadAsnKey();
            //DecryptDataMacKey();
            //TestDecryptData();
            //Generate();
            //EncryptByPublicKey();
            //DecryptByPrivateKey();
            //SignDataMicrosoft();
            //VerifySignatureMicrosoft();
            //ReadAsnKey();
            //ReadPemKey();
            //Test(1024);
            //Test(2048);

            //EncryptByXmlPublicKey();
            DecryptByXMLPrivateKey();

            Console.WriteLine("Success");
            Console.ReadLine();
        }

        private static void Generate()
        {
            const int keySize = 2048;

            //生成公私钥对
            KeyPair keyPair = KeyGenerator.GenerateKeyPair(KeyFormat.XML, keySize);

            //转换成不同的格式
            KeyPair asnKeyPair = keyPair.ToASNKeyPair();
            KeyPair xmlKeyPair = asnKeyPair.ToXMLKeyPair();
            KeyPair pemKeyPair = xmlKeyPair.ToPEMKeyPair();

            //保存公私钥
            File.WriteAllText("private.key", asnKeyPair.PrivateKey);
            File.WriteAllText("public.key", asnKeyPair.PublicKey);

            //XML格式
            File.WriteAllText("private.xml", xmlKeyPair.PrivateKey);
            File.WriteAllText("public.xml", xmlKeyPair.PublicKey);

            Console.WriteLine("Generate Success");
        }

        private static void DecryptDataMacKey()
        {
            string key = "fKpiCXIkJ9Mk4ZnXpWd/5jtu8ib0dTgOzBZp/9EgtjqxNC7cT+YfL2YDMObjFS9AsUecP3uk3R5X3Oos2G/Xz2iqsgbePXHVDMny551chHGdIYse3LwZE08fiI/cgyB16kQSPQSmJhuegwXG8n+ahCyK055JoiYwmXGSvmPqv4dh/K29+0UWmRqYZjQptTpKD7fH9nFMR1TthHZS3sFKW6cFg4ZQ5aDGZBVFJDqOtOLZzpMeSdVoCC5pWWnnXwaANzYZD6v2MbZV3Nvl5no2GMVHRtjBO/9MrFifnd1Y1DNKkzoBGmvVFm7uRtEAPyDExL7Tiey47+t2OUTtD9vtRFQSLze8oszSnb0rgIEcJKE7+guPykkpFOp02OWg7ytVqpqelTU8TgJuT9Ep0UKWJZaH1QhS+9UCTYd7koBwVdSURss6g4PeHr09x+JesK5cJIfl9Xq/QnqMXlsq6jiDkpN1gjIocmfAQ04z5Oz8QNNXesQ0SR9uCN4zIXGyLPqsT2qCmjzvkngXfx90JhS/CRH/7VBbXni1SMg6Nc0EfGfLbS7AImrpgphX0/SGYr0OaXemC5CASPqBjUc0w6c1i2QFP8JrP1P/I5N7nvrJ4WOgN8tGoRDLsZe7r+qHrtCSQ3RRDwwq7JaWJ5aSVm4TR5ReFTs2RelXzGE9oYuj7F4=";

            string strPrivate = File.ReadAllText(@"Keys\mrch-rsaPrivate.key");
            var privateKey = new KeyWorker(strPrivate, KeyFormat.ASN);

            string aesKey = privateKey.Decrypt(key);
            Console.WriteLine(aesKey);
        }

        private static void TestDecryptData()
        {
            string strPrivate = File.ReadAllText(@"Keys\mrch-rsaPrivate.key");

            string strPublic = File.ReadAllText(@"Keys\mrch-rsaPublic.key");

            var privateKey = KeyPair.ImportASNKey(strPrivate);
            var publicKey = KeyPair.ImportASNKey(strPublic);

            //var encryptData = publicKey.GenerateWorker().Encrypt("test");

            string encryptData = @"m9A74CmvOEdXSD39Xc8b8mE6nNWCzD+EowtB6EoPHfnn6uEcczk1dMpPJSjv4+W308aoRaAC+Qr3bFo+snMX8nQI/+VJdq7x9YixuTjiRMjOKLKboDLNh6qR97+KDP9jsJjPrwIgUUWmNki+sVwjiPI0CPnWNeCUtn0/zZtIDD31Ybqq0scvhp0oojSe0gBX36DaKH800/94O4WHD5el02A0kUVqkaMiM7mdUYSe63LRxs9FfDG1X+mm6kLwT3GCcfjNVIml0zQ8Ay7jVxwsjGDdD1Kbg+WsYFeVj6s+ivwCb/gXfMLzVuiAGSY2dOiISSNrOCLe8n3d4NYVVT3tljnJd0+7pxhAvtjb0uBTlA2IXq8xGRPypqnL4R1tpt4oZHeFvSfUdy+GFUJovsc1xp4nekMTCZRqkAz2KSweSOjzeViZ/3MXC26NxN833JpEs9HFyYLhNhxH0ZSxH+Ua/7+rPaKCsBUN0RQ8gR7IkV+wR6wFntS9TR+sQiP9Dr77RZzANfsjaEoj7VZaDCQIw/ZoNw2MEcA2Ck9fPtjAKKU4ieZBtVQdYJjynbOwY5xFJHY6AEKtQYXGg1nP+gi5IB2cFO3GMycJyvg8zXRYnreyAwjxytyIoMzxOjufDuPOvEaP1N+ypGzdEtuhu3lIl3ggVzIEy+ogfn0LAuuCESw=";

            var result = privateKey.GenerateWorker().Decrypt(encryptData);

            Console.WriteLine(result);
        }

        private static void SignDataMicrosoft()
        {
            string strPublic = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCnEKixaNyct9I+4GFA/QqrXy8K+K2isYhKz9MLwrQyfVxhle7+/SHIXNjspx8FrOCVAlNPr7AUJr9oGSL22LLAdKlUd3Z/haeiMlUdX/LtcE1itvITZlBi3lf7m/X5sq5vccr+OvT6dWSNhQlmQrQ61dclwuuyVjTKfNQpYHnVIw2CUVKjtDonf4KE/sjrti3z49DeOLLw1QzkpNkCcmdcsREDT9uXGCBcN/EsJHMYnR3WmTWBavA4SccspzX23nJSSKSzCP5zZT2XVh1W3mP10c3GILdMczKhEMIfWKwhdfQ7jPOiwMmCBpoGVDNTKJOSi4bxYT+GRjV7SLJD/LQIDAQAB";
            String msPriKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsKcQqLFo3Jy30j7gYUD9CqtfLwr4raKxiErP0wvCtDJ9XGGV7v79Ichc2OynHwWs4JUCU0+vsBQmv2gZIvbYssB0qVR3dn+Fp6IyVR1f8u1wTWK28hNmUGLeV/ub9fmyrm9xyv469Pp1ZI2FCWZCtDrV1yXC67JWNMp81ClgedUjDYJRUqO0Oid/goT+yOu2LfPj0N44svDVDOSk2QJyZ1yxEQNP25cYIFw38SwkcxidHdaZNYFq8DhJxyynNfbeclJIpLMI/nNlPZdWHVbeY/XRzcYgt0xzMqEQwh9YrCF19DuM86LAyYIGmgZUM1Mok5KLhvFhP4ZGNXtIskP8tAgMBAAECggEAMQz1Rs68JVqUTUllOggi/euO8A7b/6Ii+w45F1MzHxqpizb4Mvm+lfVrh5fzn2YMFkMG02BNp0EIMYH8qFzkunay2IzHpY0XvAT1iNJ6zxbSdPCfD0cKdpdUNvgY98A9VediN488K87bJbpey3iZL7UxHg32gEtHkKMLmSEJWiO3daLivlG4sNYd1AOQLyCr/kCBNaXSolFSyNKDsJSQxVNEV9xn1EZo6NA0C2qWXm/c2SCYKSZl9Te1DDbaFVpI9ZQ+cYEE/lm4SmtXBaEl0n8hV9r3RZ5Ex/U1CCSpkfDwqBW2Ulwcic3MmSQCGVrTKslpKcvIJEt0ZbKAQ6F0AQKBgQDxvbG/eO5uC5QfzxrD5PSuGdYbsEvxZc9RtRYJ+YZZzmO25IDCP83oqdo+Kpqncm610uehWd7H3PsTZpmlaELWMnNvGkrQS0j83KvKm0mjtZ+n8yotwGc0nHst0bgdU4rQDz1aFdzFa8pvlzcyP9aDeX338jETAB+K8IMAZ5otHQKBgQC2UXETJEcDeTbrlVhb9PfIH6gwGezQp7icH0jmmS/SkCq3QCa8l4dXWKDivp93QkbWBV8OsGZic53u+etz/rnqoTqHOsNdO6Oeh7xvmQPN3Ede8RVZir2Wf6tDmJdSTq5veLMQ1E/vhUr1qpfjKnw9YRU6k4/Z0js3S9Ftb2NNUQKBgQDD0zfG9I6oxGZkch+rarAuzK0d1u1eCmwsMzY8NE76Nu+du3L2aDtD6zvouhh35oH6dnO+yA9o9gDJ0YZLcK8b1tidur26CBKDC7t6L9sya7F+msOjNkYkX1KFZmrwDrnXG1FGxYkGv+/H/8Xtxbre3C8ICMBqNOJYacalMEe7nQKBgFspygKqRyADgmS2HqKMkUFuIuk6bWHAG91k/0zfGDyPfex3lWcD1dblKD1418AIUec+dFOh/PAJo9UU/pjXrBsYV227AmkiIyRn9t9Ogcpz9PQSVHyblUUlvXtlV3T+htaSYeduYjIAUoUYsi4S1mDSpIzPsERYjOePb77qzZqhAoGAB4Jp3VV65if6PaK4q+gTXpHkMC8RHHl3dw6DWkcjpa2cJ1UB01b4Or9TrcbQ/GfmBPp3TSfqgx7rqcdcGgOuq4d7eRaPeYtvAms3The6/FoL7mES70fUvvY63afamO4bGTdA93WADkSWeObRfW3di4lGnauw9OVXWSvFTFjLqP0=";

            string rawData = "eyJyZXF1ZXN0SUQiOiI1NWYyYTY1MjRmNWM5Iiwic2VydmljZSI6Im1zMmhiLnRyYWRlLm9wZW4iLCJtaWQiOiIxMTA1MjQiLCJsY1R5cGUiOiJDUDMwMSIsIm9wZW5UeXBlIjoiMCIsIm9yZGVySUQiOiIxNDQxOTY1NTc2NjA1IiwiZGlmU3RhdGVUaW1lU2NvcEpzb24iOiJ7XCJSRUNWQ1JFRFZBTElEVElNRVwiOjE0NDAwMDAsXCJSRU1JTkRESVNGUkVFWkVWQUxJRFRJTUVcIjoxNDQwMDAwLFwiQ09ORklSTVZBTElEVElNRVwiOjE0NDAwMDB9IiwicmV0dXJuVXJsIjoiXC9jaWZwYXlcL3N1Y2Nlc3NcL3N1Y2Nlc3MuanNwIiwibm90aWNlVXJsIjoiaHR0cDpcL1wvc2l0LmNpZnBheS5jb21cL3N1Y2NjZXNcL3N1Y2Nlc3MuanNwIiwiZ29vZHNOYW1lIjoiXHU2ZDRiXHU4YmQ1XHU1NTQ2XHU1NGMxIiwicHJpY2UiOiIyMDAiLCJxdWFudGl0eSI6IjEiLCJ0b3RhbEZlZSI6IjIwMCIsImZlZVR5cGUiOiJDTlkiLCJwYXllckluZm9Kc29uIjoie1wiUEFZRVJNT0JJTEVcIjpcIjYyMTIyNjQ1ODg4ODYyNDQ1OTlcIixcIlBBWUVSQkFOS0lEXCI6XCIxODg0NDk2MjIzM1wifSIsIm1yY2hPcmRlclVybCI6IjIwMCIsImlzQXV0b1JlY3YiOiJNIiwicmVxdWVzdFRpbWUiOiIyMDE1MDkxMTEyMDk1MDAwMCIsInJlbWFyayI6IjIwMCIsIm9wZW5CYW5rQ29kZSI6IklDQkMifQ==";
            //string rawData = File.ReadAllText("data.json");

            var privateKey = KeyPair.ImportASNKey(msPriKey);
            var privateKeyPem = privateKey.ToPEMKeyPair();

            var publicKey = KeyPair.ImportASNKey(strPublic);

            string signData = privateKey.GenerateWorker().SignDataMicrosoft(rawData);
            Console.WriteLine(signData);

            bool signSuccess = publicKey.GenerateWorker().VerifySignatureMicrosoft(signData, rawData);
            Console.WriteLine(signSuccess);
        }

        private static void VerifySignatureMicrosoft()
        {
            string strPublic = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCnEKixaNyct9I+4GFA/QqrXy8K+K2isYhKz9MLwrQyfVxhle7+/SHIXNjspx8FrOCVAlNPr7AUJr9oGSL22LLAdKlUd3Z/haeiMlUdX/LtcE1itvITZlBi3lf7m/X5sq5vccr+OvT6dWSNhQlmQrQ61dclwuuyVjTKfNQpYHnVIw2CUVKjtDonf4KE/sjrti3z49DeOLLw1QzkpNkCcmdcsREDT9uXGCBcN/EsJHMYnR3WmTWBavA4SccspzX23nJSSKSzCP5zZT2XVh1W3mP10c3GILdMczKhEMIfWKwhdfQ7jPOiwMmCBpoGVDNTKJOSi4bxYT+GRjV7SLJD/LQIDAQAB";
            String msPriKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCsKcQqLFo3Jy30j7gYUD9CqtfLwr4raKxiErP0wvCtDJ9XGGV7v79Ichc2OynHwWs4JUCU0+vsBQmv2gZIvbYssB0qVR3dn+Fp6IyVR1f8u1wTWK28hNmUGLeV/ub9fmyrm9xyv469Pp1ZI2FCWZCtDrV1yXC67JWNMp81ClgedUjDYJRUqO0Oid/goT+yOu2LfPj0N44svDVDOSk2QJyZ1yxEQNP25cYIFw38SwkcxidHdaZNYFq8DhJxyynNfbeclJIpLMI/nNlPZdWHVbeY/XRzcYgt0xzMqEQwh9YrCF19DuM86LAyYIGmgZUM1Mok5KLhvFhP4ZGNXtIskP8tAgMBAAECggEAMQz1Rs68JVqUTUllOggi/euO8A7b/6Ii+w45F1MzHxqpizb4Mvm+lfVrh5fzn2YMFkMG02BNp0EIMYH8qFzkunay2IzHpY0XvAT1iNJ6zxbSdPCfD0cKdpdUNvgY98A9VediN488K87bJbpey3iZL7UxHg32gEtHkKMLmSEJWiO3daLivlG4sNYd1AOQLyCr/kCBNaXSolFSyNKDsJSQxVNEV9xn1EZo6NA0C2qWXm/c2SCYKSZl9Te1DDbaFVpI9ZQ+cYEE/lm4SmtXBaEl0n8hV9r3RZ5Ex/U1CCSpkfDwqBW2Ulwcic3MmSQCGVrTKslpKcvIJEt0ZbKAQ6F0AQKBgQDxvbG/eO5uC5QfzxrD5PSuGdYbsEvxZc9RtRYJ+YZZzmO25IDCP83oqdo+Kpqncm610uehWd7H3PsTZpmlaELWMnNvGkrQS0j83KvKm0mjtZ+n8yotwGc0nHst0bgdU4rQDz1aFdzFa8pvlzcyP9aDeX338jETAB+K8IMAZ5otHQKBgQC2UXETJEcDeTbrlVhb9PfIH6gwGezQp7icH0jmmS/SkCq3QCa8l4dXWKDivp93QkbWBV8OsGZic53u+etz/rnqoTqHOsNdO6Oeh7xvmQPN3Ede8RVZir2Wf6tDmJdSTq5veLMQ1E/vhUr1qpfjKnw9YRU6k4/Z0js3S9Ftb2NNUQKBgQDD0zfG9I6oxGZkch+rarAuzK0d1u1eCmwsMzY8NE76Nu+du3L2aDtD6zvouhh35oH6dnO+yA9o9gDJ0YZLcK8b1tidur26CBKDC7t6L9sya7F+msOjNkYkX1KFZmrwDrnXG1FGxYkGv+/H/8Xtxbre3C8ICMBqNOJYacalMEe7nQKBgFspygKqRyADgmS2HqKMkUFuIuk6bWHAG91k/0zfGDyPfex3lWcD1dblKD1418AIUec+dFOh/PAJo9UU/pjXrBsYV227AmkiIyRn9t9Ogcpz9PQSVHyblUUlvXtlV3T+htaSYeduYjIAUoUYsi4S1mDSpIzPsERYjOePb77qzZqhAoGAB4Jp3VV65if6PaK4q+gTXpHkMC8RHHl3dw6DWkcjpa2cJ1UB01b4Or9TrcbQ/GfmBPp3TSfqgx7rqcdcGgOuq4d7eRaPeYtvAms3The6/FoL7mES70fUvvY63afamO4bGTdA93WADkSWeObRfW3di4lGnauw9OVXWSvFTFjLqP0=";

            //string rawData = @"11111111";
            //string rawData =File.ReadAllText("data.json");
            String rawData =
                "IntcInJlcXVlc3RJRFwiOlwiNTVmMTU5NGYwOWYyOFwiLFwic2VydmljZVwiOlwibXMyaGIudHJhZGUub3BlblwiLFwibWlkXCI6XCIxMTA1MjRcIixcImxjVHlwZVwiOlwiQ1AzMDFcIixcIm9wZW5UeXBlXCI6XCIwXCIsXCJvcmRlcklEXCI6XCIxNDQxODgwMzk3NzYyXCIsXCJkaWZTdGF0ZVRpbWVTY29wSnNvblwiOlwie1xcXCJSRUNWQ1JFRFZBTElEVElNRVxcXCI6MTQ0MDAwMCxcXFwiUkVNSU5ERElTRlJFRVpFVkFMSURUSU1FXFxcIjoxNDQwMDAwLFxcXCJDT05GSVJNVkFMSURUSU1FXFxcIjoxNDQwMDAwfVwiLFwicmV0dXJuVXJsXCI6XCJcXFwvY2lmcGF5XFxcL3N1Y2Nlc3NcXFwvc3VjY2Vzcy5qc3BcIixcIm5vdGljZVVybFwiOlwiaHR0cDpcXFwvXFxcL3NpdC5jaWZwYXkuY29tXFxcL3N1Y2NjZXNcXFwvc3VjY2Vzcy5qc3BcIixcImdvb2RzTmFtZVwiOlwiXFx1NmQ0YlxcdThiZDVcXHU1NTQ2XFx1NTRjMVwiLFwicHJpY2VcIjpcIjIwMFwiLFwicXVhbnRpdHlcIjpcIjFcIixcInRvdGFsRmVlXCI6XCIyMDBcIixcImZlZVR5cGVcIjpcIkNOWVwiLFwicGF5ZXJJbmZvSnNvblwiOlwie1xcXCJQQVlFUk1PQklMRVxcXCI6XFxcIjYyMTIyNjQ1ODg4ODYyNDQ1OTlcXFwiLFxcXCJQQVlFUkJBTktJRFxcXCI6XFxcIjE4ODQ0OTYyMjMzXFxcIn1cIixcIm1yY2hPcmRlclVybFwiOlwiMjAwXCIsXCJpc0F1dG9SZWN2XCI6XCJNXCIsXCJyZXF1ZXN0VGltZVwiOlwiMjAxNTA5MTAxMjA5NTkwMDBcIixcInJlbWFya1wiOlwiMjAwXCIsXCJvcGVuQmFua0NvZGVcIjpcIklDQkNcIn0i";

            string mac = @"YWl2dUB3iFBK6KfgsflIqn82ibHLTUVWd+lf5emtaMzzgYiuWAl+YiVphxhzBOlq8cDDpFx60jVo9CuVWN//VnFfw0dWwBw3IDikPEpURFiNLf7SJ4feintGecXZBRfEtxBvUXW20hYFijD1CBVUNtwaeywQZEZB3r4POaLMV4hrCG8jWzb4trMrVZ4Nlp29QwwkJ4klwvLrC9lwMTq/9LEH5B+UEQ9PvhF6UyFoajRTiEbdT1GkVPWn7h3M37jY/4c2ln549uFFJA7RiCwS00xutWmAtbCEzg5G6q84vBnEn6vLP9r1AL0fw9KVtJsygf103KBhFwq//jA8ggRcpA==";

            //mac = Encoding.UTF8.GetString(Convert.FromBase64String(mac));

            var publicKey = KeyPair.ImportASNKey(strPublic);
            var privateKey = KeyPair.ImportASNKey(msPriKey);
            var s = privateKey.ToPEMKeyPair().PrivateKey;

            mac = privateKey.GenerateWorker().SignDataMicrosoft(rawData);
            bool signSuccess = publicKey.GenerateWorker().VerifySignatureMicrosoft(mac, rawData);

            Console.WriteLine(signSuccess);
        }

        private static void ReadAsnKey()
        {
            string strPrivate = File.ReadAllText(@"Keys\mrch-rsaPrivate.key");

            string strPublic = File.ReadAllText(@"Keys\mrch-rsaPublic.key");

            var privateKey = KeyPair.ImportASNKey(strPrivate);
            var publicKey = KeyPair.ImportASNKey(strPublic);

            //公钥加密
            var rawData = "MgW46k89vmyplD9Lg7fLT2qAMrYdfiic5wjoSt1Y+er+sSJL+a9wK6bxOwrwQ0fnNTwR4zL/PoE7+sRSjYxWzhA4hxPWPwzaGPPrsCWipoFwnTLU5ff6ZMiAOGDyDOXu4rooicO7F0wSpg8Nj5hegq0Lem/XOvL7em/P86AlbElV2bkPmAz1xl0E2zkmRY+qi0H52+PmBb3JhRMQElQTO4T15cb9vchUu1LAEnRUWVSazAuj/YtMEJEvykPETm2PfQ8ch7L0I4cMOP1zFIORvrA+Z7oZC7Ide96jnGM8yKfWGjY/aj/CIOVijBXz+1kpqCN5QLhdnWI4OJhOteudxE+uqUDyEkM2xJqqBE2mXLNV5UiKDXN43QAl//h/IYc8/jGL7OPRcD8x2pHLxjoMYVvF6KufvSLj0PkB5AU2cfJRJa5Uzom9gwvnLjlvTsyOVSxhVXRXXCmyL32fo27HuwRAVJYTXIvMUqpfmWnYkNLnHt36gVCFqHW623KTYNOpUtgQ04vrQrYgOa0AF0Lu+J4BChPKUrBJyQ/RnoNtzITPXgQ34j/jq34+z2Ne3Qj6yHhpYXomwySn9aK1D+dWYAY+5Vcpd7nrgLeC/8ASyvcD7J15C0td8RdM/EKskPhfVToGHq3V/DGSb2rkH4W+ywNuBSLSgER22mpR2K8Iz5JOPdvSDEkHgphudTWr50SOTeM93hYe0N4QjENPWuh01rcrCTA39ZbhWVs3UsRX4NxIrsxsIpYtLwkHGtkRXdtGy/qTi7JMX/+qLYzb3980dmXep5gA8OAvkWB8G6TXrYL6MTHeGl2WmGpzll9IkkE9oATkTgggNrZo4sQE+Imzd8C5ZVP5aH+cplMqQBLnYpAmInoxubIuFF+Zr8hZ9nkPAGOnBM0vQp3W5ALFxHzBYCFErgD1k9xzcJZLxMYvSiVmWCE+u2XJnW3oiJFfKQEA+O5il86ONkYeRtxcMYTcFW0TRR0jwri1uqnz4VjOa+mzJLj+IiPnj65eFqSlsQhD";

            var encryptData = publicKey.GenerateWorker().Encrypt(rawData);

            var result = privateKey.GenerateWorker().Decrypt(encryptData);

            Console.WriteLine(string.Compare(rawData, result) == 0);
        }

        private static void ReadPemKey()
        {
            string strPrivate = File.ReadAllText(@"Keys\rsa_private_key.pem")
                                    .Split(new string[] { "-----" }, StringSplitOptions.RemoveEmptyEntries)[1]
                                    .Replace(" ", "").Replace("\r", "").Replace("\n", "");

            string strPublic = File.ReadAllText(@"Keys\rsa_public_key.pem")
                                   .Split(new string[] { "-----" }, StringSplitOptions.RemoveEmptyEntries)[1]
                                   .Replace(" ", "").Replace("\r", "").Replace("\n", "");

            var privateKey = KeyPair.ImportASNKey(strPrivate);
            var publicKey = KeyPair.ImportASNKey(strPublic);

            //公钥加密
            var rawData = "311111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111113";

            var result = publicKey.GenerateWorker().Encrypt(rawData);

            Console.WriteLine(result);

            string data = privateKey.GenerateWorker().Decrypt(result);

            Console.WriteLine(data);
        }

        private static void EncryptByPublicKey()
        {
            string strPublic = File.ReadAllText(@"Keys\public.key");
            var publicKey = KeyPair.ImportASNKey(strPublic);

            string rawData = "eyJyZXR1cm5VcmwiOiJodHRwOi8vMTI3LjAuMC4xOjkwMDMvbGNfbWVyY2hhbnQvcmV0dXJuVmlldyIsImRpZlN0YXRlVGltZVNjb3BKc29uIjoie1wiQ09ORklSTVZBTElEVElNRVwiOlwiNjA0ODAwMDAwXCIsXCJSRUNWQ1JFRFZBTElEVElNRVwiOlwiODY0MDAwMDBcIixcIlJFTUlORERJU0ZSRUVaRVZBTElEVElNRVwiOlwiNjA0ODAwMDAwXCJ9IiwicmVjZWl2ZXIiOiIiLCJwYXllckluZm9Kc29uIjoie1wiUEFZRVJNT0JJTEVcIjpcIjE4ODQ0OTYyMjMzXCIsXCJQQVlFUkJBTktJRFwiOlwiNjIxMjI2NDU4ODg4NjI0NDU5OVwifSIsInNoaXBGZWUiOiIiLCJpc0F1dG9SZWN2IjoiTSIsIm9wZW5UeXBlIjowLCJwYXllck1vYmlsZSI6IiIsImZlZVR5cGUiOiJDTlkiLCJyZWN2QmFua0NvZGUiOiJJQ0JDIiwicXVhbnRpdHkiOiIxIiwibGNOTyI6IumTtuS/oeivgSoxNzcuMDBSTUIqMTEwNTI0SUNCQzIwMTUwODA2MTY0MzE1IiwicmVjdkNvbnRhY3QiOiIiLCJpc1NoaXAiOiIiLCJtcmNoTmFtZSI6IuiejUUt57u05Lmf57qzIiwib3JkZXJJRCI6IklDQkMyMDE1MDgwNjE2NDMxNSIsImxjSUQiOiJJQ0JDXzY2OTUwNjMzMDEyMDE0NV8yMDE1MDgwNjE2NDMzMSIsIm5vdGljZVVybCI6Imh0dHA6Ly8xMjcuMC4wLjE6OTAwMy9sY19tZXJjaGFudC90cmFkZSIsInJlY3ZCYW5rQ2FyZCI6IiIsIm1yY2hPcmRlclVybCI6Imh0dHA6Ly8xMjcuMC4wLjE6OTAwMy9sY19tZXJjaGFudC93eW4vb3JkZXJEZXRhaWwiLCJ0b3RhbEZlZSI6IjE3NzAwIiwicHJpY2UiOiIxNzcwMCIsInBheWVyIjoiIiwibGNUeXBlIjoiQ1AzMDAiLCJzZXJ2aWNlIjoicmgyb2gudHJhZGUucHJlT3BlbiIsIm9wZW5CYW5rQ29kZSI6IklDQkMiLCJtaWQiOiIxMTA1MjQiLCJnb29kc05hbWUiOiLnu7TkuZ/nurPphZLlupfvvIjmt7HlnLPpvpnljY7msJHmsrvlpKfpgZPkuIfkvJfln47lupfvvIkg57uP5rWO5oi/IiwicmVjdkFkZHJlc3MiOiIiLCJwYXllckJhbmtDYXJkTk8iOiIifQ==";

            string data = publicKey.GenerateWorker().Encrypt(rawData);

            var test = publicKey.GenerateWorker().Decrypt(data);
        }

        private static void DecryptByPrivateKey()
        {
            string data = @"bYDRx+mJl9DyrMn5P6gDqBk/mLR0IKw0bN3s3nRvgobfeZQWyfd8ePfzxomcvCMFxfWUVXh7zV8rvCsbjp5ioH+T8BI9X5o2YqkOG+KSfp7N6M2s+YwT4L0PDBH0jl6RbG655JnJ8fy0ulXV1FvG7N75rtr/Jy2WzIJyUc+1b36t7jRMjjFXgn3vFiWYvOWqkVEgIwbovIX30TsvONt06gE0n7zZCVEkA1ZtI5SmKTyNZhbu+a/mZbxnaRbISCuc/wJ1F6AA0VVMnZayrVUid5FY5DKQTurlRfKX9vMCqQ1/L7z1GU2yWtSsQgh2I1Wrf6Gfx54XjZPVjX8Vj1yE2A==";

            string strPrivate = File.ReadAllText(@"Keys\mrch-rsaPrivate.key");
            var privateKey = KeyPair.ImportASNKey(strPrivate);

            string strPublic = File.ReadAllText(@"Keys\mrch-rsaPublic.key");
            var publicKey = KeyPair.ImportASNKey(strPublic);

            string rawData = privateKey.GenerateWorker().Decrypt(data);

            string aesKey = Encoding.UTF8.GetString(Convert.FromBase64String(rawData));
        }

        private static void EncryptByXmlPublicKey()
        {
            string strPublic = File.ReadAllText(@"Keys\xml_public.xml");
            var publicKey = KeyPair.ImportXMLKey(strPublic);

            string rawData = "cifpay";

            string data = publicKey.GenerateWorker().Encrypt(rawData);
            Console.WriteLine("加密结果：" + data);
        }

        private static void DecryptByXMLPrivateKey()
        {
            string strPrivate = File.ReadAllText(@"Keys\xml_private.xml");
            var privateKey = KeyPair.ImportXMLKey(strPrivate);

            //string rawData = "XgMMhT90rtc9nO7LkGfGdpub9iHIneVyJMbLw1C3pF/SVDOZx/S5sEwRUWPXYN2UDk6EDNB/jaT9ScrMqg0SCgEu1VTQNvlrgnDWUj/W3EnPlxc3bVlHUuJZNKAGOxiPQ9HB99Chx2P3Qah/w9uMNjG8IU2CgwSUSC6S9kXzuYNMo40OpRavYpkfcX24Nttn7XjCWLAaUMO3fT294duwpwWNGNywhnsgbwTfMw1CHGYjzaWYbWuHbOiwOOJc6MNNgragtBTZSh5GdhkWxt29q/gxq3xUGO5SRuaEKtadPtu95rpWGNmVx2SKuqVX2bsY7AlKbVbfC8UxazXQ/aTGfA==";
            string toolData = "oC7AEHqMjr5VMi7IEt4j+Yo38iXRQ3RPt2xWyc9L1CTgyC3r93DF88+v/o0K9U4DHcVtcznC+rUtXK8BXoSiyy9ALl5pzu9BYv1Yvh82Mmi78HtTZ/Eyi5NMp6qFq6iaJVUYGsfE7K83ShYqHd0iwauc7s5RHAeNeIzLuwcl+rlxlF8dqNPSL5QLCSfpmVWyBZaRsB0p4mRiFHQkJjdkEWcnfTNrQIE3sUvL2dARXXJ8KoD40Zet9m/puUZNKFeXjlrKZXzrplYQt4ecfcmbLc/np2T/80xzv+D1+22xeY3X6A2pfD5fAp0fLmB7CfXO0rzoIi1D37hY5HlWi8w5IQ==";

            string data = privateKey.GenerateWorker().Encrypt(toolData);
            Console.WriteLine("解密结果：" + data);
        }

        private static void Test(int keySize = 2048)
        {
            //const int keySize = 2048;
            Console.WriteLine("=========================== 密钥长度{0} ===========================", keySize);

            //生成公私钥对
            KeyPair keyPair = KeyGenerator.GenerateKeyPair(KeyFormat.XML, keySize);

            //转换成不同的格式
            KeyPair asnKeyPair = keyPair.ToASNKeyPair();
            KeyPair xmlKeyPair = asnKeyPair.ToXMLKeyPair();
            KeyPair pemKeyPair = xmlKeyPair.ToPEMKeyPair();

            //获取公私钥
            string privateKey = xmlKeyPair.PrivateKey;
            string publicKey = xmlKeyPair.PublicKey;

            //加解密
            KeyWorker privateWorker = new KeyWorker(privateKey, KeyFormat.XML);
            KeyWorker publicWorker = new KeyWorker(publicKey, KeyFormat.XML);

            //XML
            Console.WriteLine(privateWorker.Decrypt(publicWorker.Encrypt("你好！世界")));
            Console.WriteLine(publicWorker.Decrypt(privateWorker.Encrypt("你好！中国")));

            //ASN
            privateWorker = new KeyWorker(asnKeyPair.PrivateKey, KeyFormat.ASN);
            publicWorker = new KeyWorker(asnKeyPair.PublicKey, KeyFormat.ASN);
            Console.WriteLine(privateWorker.Decrypt(publicWorker.Encrypt("你好！世界")));
            Console.WriteLine(publicWorker.Decrypt(privateWorker.Encrypt("你好！中国")));

            //PEM
            privateWorker = new KeyWorker(pemKeyPair.PrivateKey, KeyFormat.PEM);
            publicWorker = new KeyWorker(pemKeyPair.PublicKey, KeyFormat.PEM);
            Console.WriteLine(privateWorker.Decrypt(publicWorker.Encrypt("你好！世界")));
            Console.WriteLine(publicWorker.Decrypt(privateWorker.Encrypt("你好！中国")));
        }
    }
}