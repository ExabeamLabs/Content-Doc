#### Parser Content
```Java
{
Name = cef-microsoft-app-login
  DataType = "app-login"
  Conditions = [ """CEF:""", """destinationServiceName=Office 365""", """description":"Log on"""" ]
  Fields = ${MSParserTemplates.cef-azure-app-activity-1.Fields}[
    """"1":[^=]+?"displayName":"\s*(_splunk_exo|({user_fullname}({user_lastname}[^, "]+)[,\s]+({user_firstname}[^"\(]+?))\s*|({user_email}[^@"]+@({email_domain}[^@"]+?))|({user}[^"\s]+))(\([^"]+\))?"""",
    """device <b>({dest_host}[^<]+)""",
    """"userAgent":";*({user_agent}[^"]+?);*"""",
    """"userAgent":\{"family":"(UNKNOWN|({browser}[^"]+))"""",
    """"operatingSystem":\{"name":"(Unknown|({os}[^"]+))"""",
    """"countryCode":"(--|({country_code}[^"]+))"""",
    """"Upn":"(anonymous|email|({user_email}[^@"]+@({email_domain}[^@"]+?))|({user}[^"\s]+?))"""",
    """"aadTenantId":"(Unknown|Personal|({host}[^",]+))"""",
    """"appName":"({app}[^",]+)""""
  ]
}
```