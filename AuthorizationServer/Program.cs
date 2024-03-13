namespace AuthorizationServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                // To scan the assembly for HostingStartupAttributes, the
                // ApplicationName must be set. This can be done with
                // UseSetting, Configure, or UseStartup.
                // .UseSetting(HostDefaults.ApplicationKey, "HostingStartupApp")
                // .Configure(_ => { })
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}