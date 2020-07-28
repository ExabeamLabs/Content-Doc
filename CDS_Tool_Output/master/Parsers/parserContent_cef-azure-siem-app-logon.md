#### Parser Content
```Java
{
Name = cef-azure-siem-app-logon
  Vendor = Microsoft
  Product = Microsoft CAS
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "|MCAS|SIEM_Agent|", "|EVENT_CATEGORY_", "_LOGIN|" ]
  Fields = [
    """EVENT_CATEGORY_({outcome}.+?)_LOGIN""",
    """Failure message:\s*({failure_reason}.+?)\)\s+\w+=""",
    """\ssuser=({user}[^@]+)@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))\s+""",
    """\srt=({time}\d+)""",
    """\sdestinationServiceName=({app}.+?)\s+\w+=""",
    """\srequestClientApplication=(|({user_agent}.+?))\s+\w+=""",
    """\sdvc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=({host}[^\s]+)"""
  ]
}
```