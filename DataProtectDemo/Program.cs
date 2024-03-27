using System;
using System.Security.Cryptography;
using AspNetCore.Xcode.Me;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

public class Program
{
    public static void Main(string[] args)
    {
        // add data protection services
        var serviceCollection = new ServiceCollection();
        serviceCollection.AddDataProtection();
        var services = serviceCollection.BuildServiceProvider();

        //services.GetDataProtectionProvider();

        // create an instance of MyClass using the service provider
        //var instance = ActivatorUtilities.CreateInstance<MyClass>(services);
        //instance.RunSample();

        //string password = "www.xcode.me";
        //byte[] salt = new byte[128 / 8];
        //using (var rng = RandomNumberGenerator.Create())
        //{
        //    rng.GetBytes(salt);
        //}
        //string saltString = Convert.ToBase64String(salt);

        //var hashedBytes = KeyDerivation.Pbkdf2(password, salt, prf: KeyDerivationPrf.HMACSHA1, 10000, 256 / 8);
        //string hashedString = Convert.ToBase64String(hashedBytes);

        //PasswordHasher passwordHasher = new PasswordHasher();

        //string password = "www.xcode.me";
        //var hashedpassword =  passwordHasher.HashPassword(password);

        //bool result = passwordHasher.VerifyHashedPassword(hashedpassword, "www.xcode.me");

        //Console.WriteLine(result);






    }

    public class MyClass
    {
        IDataProtector _protector;

        // the 'provider' parameter is provided by DI
        public MyClass(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector("Contoso.MyClass.v1");
        }

        public void RunSample()
        {
            //Console.Write("Enter input: ");
            //string input = Console.ReadLine();

            var input = "leo123";
            // protect the payload
            string protectedPayload = _protector.Protect(input);

            //创建子集的保护器,并使其有效期为5秒钟(超过5秒钟密码失效)
            var protector2 = _protector.CreateProtector("_son").ToTimeLimitedDataProtector();
            string protectPayLoad2 = protector2.Protect(input,lifetime: TimeSpan.FromSeconds(5));

            Console.WriteLine($"Protect returned: {protectedPayload}");

            // unprotect the payload
            string unprotectedPayload = _protector.Unprotect(protectedPayload);
            Console.WriteLine($"Unprotect returned: {unprotectedPayload}");
        }
    }
}

/*
 * SAMPLE OUTPUT
 *
 * Enter input: Hello world!
 * Protect returned: CfDJ8ICcgQwZZhlAlTZT...OdfH66i1PnGmpCR5e441xQ
 * Unprotect returned: Hello world!
 */