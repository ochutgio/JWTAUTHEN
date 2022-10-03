using InventoryService.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Threading.Tasks;

namespace InventoryService
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var connection = Configuration.GetConnectionString("InventoryDatabase");
            services.AddDbContextPool<InventoryContext>(options => options.UseSqlServer(connection));
            services.AddControllers();

            services.AddAuthentication(i =>
                    {
                        i.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                        i.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                        i.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                        i.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
                    })
                    .AddJwtBearer(options =>
                    {
                        options.RequireHttpsMetadata = true;
                        options.SaveToken = true;

                        options.TokenValidationParameters = new TokenValidationParameters()
                        {
                            ValidateIssuer = true,
                            ValidateAudience = true,
                            ValidAudience = Configuration["Jwt:Audience"],
                            ValidIssuer = Configuration["Jwt:Issuer"],
                            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:Key"]))
                        };

                        options.Events = new JwtBearerEvents();
                        options.Events.OnMessageReceived = context =>
                        {
                            if (context.Request.Cookies.ContainsKey("X-Access-Token"))
                            {
                                context.Token = context.Request.Cookies["X-Access-Token"];
                            }
                            return Task.CompletedTask;
                        };
                    })
                    .AddCookie(options =>
                    {
                        options.Cookie.SameSite = SameSiteMode.Strict;
                        options.Cookie.HttpOnly = true;
                        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                        options.Cookie.IsEssential = true;
                        options.Cookie.Expiration = System.TimeSpan.FromDays(Configuration.GetValue<int>("jwt:Expire"));
                    });

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            //app.UseCors(builder => 
            //    builder
            //    .AllowAnyHeader()
            //    .AllowAnyMethod()
            //    .AllowAnyOrigin()
            //    //.AllowCredentials()
            //);

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
