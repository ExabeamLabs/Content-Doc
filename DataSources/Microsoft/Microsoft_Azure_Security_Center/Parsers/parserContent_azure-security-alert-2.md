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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"AlertName":"({alert_name}[^"]{1,2000})""",
    """"AlertSeverity":"({alert_severity}[^"]{1,2000})""",
    """"SystemAlertId":"({alert_id}[^"]{1,2000})""",
    """"Description":"({additional_info}[^".]{1,2000}?)\.?"""",
    """"AlertType":"({alert_type}[^"]{1,2000})""",
    """"TimeGenerated":"({time}[^"]{1,2000})""", 
    """"CompromisedEntity":"({src_host}[^"]{1,2000})""",
    """"Address":\s{0,100}"({src_ip}[a-fA-F:\d.]{1,2000})""",
    """"User agent":\s{0,100}"({user_agent}[^"]{1,2000})""",
    """"Azure AD user":\s{0,100}"(N\/A\s{1,100}\(Azure AD authentication was not used\)|({user}[^"]{1,2000}))""",
    """"CountryName":\s{0,100}"({location_country}[^"]{1,2000})""",
    """"City":\s{0,100}"({location_city}[^"]{1,2000})""",
    """"AlertLink":"({malware_url}[^"]{1,2000})"""
    ]
}
```