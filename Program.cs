using System.Data;
using MySql.Data.MySqlClient;
using Dapper;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

string SECRET = "1234567890abcdefghigklmnopqrstuvwxyz";
var app = WebApplication.Create();

IDbConnection ConnectDB(){
    return new MySqlConnection("Server=localhost;Uid=root;Password=password;Database=auth");
}

string GenerateToken(string name) {
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(SECRET);
    var tokenDescriptor = new SecurityTokenDescriptor{
        Subject = new ClaimsIdentity(
            new[] {
                new Claim("name", name)
            }
        ),
        Expires = DateTime.UtcNow.AddDays(1),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
}
string? VerifyToken(string? token) {
    if(token == null) {
        return null;
    }
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(SECRET));
    try
    {
        tokenHandler.ValidateToken(token, new TokenValidationParameters{
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateIssuer = false,
            ValidateAudience = false,
        }, out SecurityToken validatedToken);
        var jwtToken = (JwtSecurityToken)validatedToken;
        var name = jwtToken.Claims.First(x=>x.Type == "name").Value;
        return name;
    }
    catch (System.Exception e)
    {
        Console.WriteLine(e.Message);
        return null;
    }
}
app.UseWhen(context => context.Request.Path.StartsWithSegments("/protected"), a=>a.Use(
    async(HttpContext context, RequestDelegate next) => {
        var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
        var name = VerifyToken(token);
        if(name != null) {
            context.Items["username"] = name;
            await next(context);
        } else {
            await context.Response.WriteAsync("Auth failed");
        }
    }
));
app.MapGet("/", ()=>"Hello World");
app.MapGet("/protected/welcome" , (HttpContext context)=>{
    var name = context.Items["username"];
    return "Welcome " + name;
});
app.MapPost("/register", async(User user)=>{
    var cnn = ConnectDB();
    try
    {
        cnn.Open();
        var dbUser = await cnn.QueryAsync("SELECT * FROM users WHERE username = '" + user.Username + "';");
        if(dbUser.FirstOrDefault() != null) {
            return "Username already registered,please change username";
        }
        var hashPassword = BCrypt.Net.BCrypt.HashPassword(user.Password);
        await cnn.QueryAsync("INSERT INTO users(username, password) VALUES('" + user.Username +"','" + hashPassword + "');");
        cnn.Close();
        return "Username register successfully!";
    }
    catch (System.Exception e)
    {
        Console.WriteLine(e.Message);
        throw;
    }
});
app.MapPost("/login", async(User user)=>{
    if(user.Username == null) {
        return "Username must not be null";
    }
    var cnn = ConnectDB();
    try
    {
        cnn.Open();
        var dbUser = await cnn.QueryAsync("SELECT * FROM users WHERE username = '" + user.Username + "';");
        if(dbUser.FirstOrDefault() == null) {
            return "Username not registered";
        }
        var isValid = BCrypt.Net.BCrypt.Verify(user.Password, dbUser.First().password);
        if(!isValid){
            return "Password not right";
        }
        string token = GenerateToken(user.Username);
        return token;
    }
    catch (System.Exception e)
    {
        Console.WriteLine(e.Message);
        throw;
    }
});
app.Run();

class User {
    public int Id {get; set;}
    public string? Username {get; set;}
    public string? Password {get; set;}
}