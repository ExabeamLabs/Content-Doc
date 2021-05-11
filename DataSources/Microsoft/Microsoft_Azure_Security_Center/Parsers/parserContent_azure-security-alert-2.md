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
    """"Address":\s{0,100}"({src_ip}[a-fA-F:\d.]+)""",
    """"User agent":\s{0,100}"({user_agent}[^"]+)""",
    """"Azure AD user":\s{0,100}"(N\/A\s{1,100}\(Azure AD authentication was not used\)|({user}[^"]+))""",
    """"CountryName":\s{0,100}"({location_country}[^"]+)""",
    """"City":\s{0,100}"({location_city}[^"]+)""",
    """"AlertLink":"({malware_url}[^"]+)"""
    ]
}
```