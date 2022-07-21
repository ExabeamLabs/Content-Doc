#### Parser Content
```Java
{
Name = beyondtrust-passwordsafe-app-login-1
  Vendor = BeyondTrust
  Product = BeyondTrust PasswordSafe
  Lms = Syslog
  DataType = "app-login"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """"vendor":"BeyondTrust"""", """"eventname":"Login"""", """"category":"Login"""", """"product":"BeyondInsight"""", """"systemname":"Login"""" ]
  Fields = [
    """"host":"({host}[^"]{1,2000})"""",
    """"createdate":"({time}\d{1,2}\/\d{1,2}\/\d\d\d\d\s\d{1,2}:\d{1,2}:\d{1,2}\s\w{1,2})"""",
    """"username":"(({domain}[^\\"]{1,2000})\\{1,20})?({user}[^"]{1,2000})"""",
    """"(sourceip|ipaddress)":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """"sourcehost":"({src_host}[^"]{1,2000})"""",
    """"({app}BeyondInsight)"""",
    """"category":"({event_name}[^"]{1,2000})"""",
    """"eventname":"({additional_info}[^"]{1,2000})""""
  ]


}
```