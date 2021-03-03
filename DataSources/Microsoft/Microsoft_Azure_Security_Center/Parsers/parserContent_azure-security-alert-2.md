#### Parser Content
```Java
{
Name = azure-security-alert-2
  Vendor = Microsoft
  Product = Microsoft Azure Security Center
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"ProductName":"Azure Security Center"""","""CEF""", """|SkyFormation Cloud Apps Security|""", """destinationServiceName=Azure""", """dproc=Log Analytics OMS Workspace""", """"Type":"SecurityAlert"""" ]
  Fields=[
    """exabeam_host=({host}[\w.\-]+)""",
    """"AlertName":"({alert_name}[^"]+)""",
    """"AlertSeverity":"({alert_severity}[^"]+)""",
    """"SystemAlertId":"({alert_id}[^"]+)""",
    """"Description":"({additional_info}[^".]+?)\.?"""",
    """"AlertType":"({alert_type}[^"]+)""",
    """"TimeGenerated":"({time}[^"]+)""", 
    """"CompromisedEntity":"({src_host}[^"]+)""",
    """"Address":\s*"({src_ip}[a-fA-F:\d.]+)""",
    """"User agent":\s*"({user_agent}[^"]+)""",
    """"Azure AD user":\s*"(N\/A\s+\(Azure AD authentication was not used\)|({user}[^"]+))""",
    """"CountryName":\s*"({location_country}[^"]+)""",
    """"City":\s*"({location_city}[^"]+)""",
    """"AlertLink":"({malware_url}[^"]+)"""
    ]
}
```