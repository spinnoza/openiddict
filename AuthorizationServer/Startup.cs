using AuthorizationServer.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;

namespace AuthorizationServer
{
    public class Startup
    {
        private readonly IConfiguration _configuration;
        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            // services.AddMvc(options => options.EnableEndpointRouting = false);
            services.AddRazorPages();
            // services.AddControllersWithViews(options => options.EnableEndpointRouting = false);
            services.AddControllers(options => options.EnableEndpointRouting = false);
            services.AddDbContext<AppDbContext>(options =>
            {
                options.UseSqlServer(_configuration.GetConnectionString("DefaultConnection"));
                options.UseOpenIddict();
            });

            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);

            services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.UseEntityFrameworkCore()
                        .UseDbContext<AppDbContext>();
                })
                .AddServer(options =>
                {
                    // // 允許 auth server 支援 client credentials grant
                    // options.AllowClientCredentialsFlow();

                    

                    options
                        // 設定取得 access token 的 endpoint
                        .SetTokenEndpointUris("/connect/token")
                        .SetAuthorizationEndpointUris("connect/authorize")
                        // 設定 introspection endpoint
                        // .SetIntrospectionEndpointUris("/connect/introspect")
                        .SetLogoutEndpointUris("connect/logout")
                        ;

                    options.AllowAuthorizationCodeFlow();

                    //options
                    //    // 產生開發用的加密金鑰，production 建議用存在本機的 X.509 certificates
                    //    .AddEphemeralEncryptionKey()
                    //    .AddEphemeralSigningKey()
                    //    // 停用 access token 加密，production 不建議使用
                    //    .DisableAccessTokenEncryption()
                    //    ;

                    options.AddDevelopmentEncryptionCertificate();
                    options.AddDevelopmentSigningCertificate();

                    options
                        .UseAspNetCore()
                        .EnableLogoutEndpointPassthrough()
                        .EnableAuthorizationEndpointPassthrough()
                        .EnableTokenEndpointPassthrough()
                        ;

                });

            

            //services.AddControllersWithViews(options => options.EnableEndpointRouting = false);
            // services.AddHostedService<TestClient>();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
            }


            using (var scope = app.ApplicationServices.CreateScope())
            {
                var seeder = scope.ServiceProvider.GetRequiredService<ClientsSeeder>();
                seeder.AddClients().GetAwaiter().GetResult();
                //seeder.AddScopes().GetAwaiter().GetResult();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

          
            app.UseAuthentication();
            app.UseAuthorization();

            //app.mapcontroller();
            app.UseMvcWithDefaultRoute();
            

        }
    }
}
