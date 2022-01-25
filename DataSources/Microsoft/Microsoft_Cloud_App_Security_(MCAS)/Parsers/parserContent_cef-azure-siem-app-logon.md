#### Parser Content
```Java
{
Name = cef-azure-siem-app-logon
  Vendor = Microsoft
  Product = Microsoft Cloud App Security (MCAS)
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "|MCAS|SIEM_Agent|", "|EVENT_CATEGORY_", "_LOGIN|" ]
  Fields = [
    """EVENT_CATEGORY_({outcome}.+?)_LOGIN""",
    """Failure message:\s{0,100}({failure_reason}.+?)\)\s{1,100}\w+=""",
    """\ssuser=({user}[^@]{1,2000})@([\.\w+]{1,2000}\.)?({email_domain}[^\.\s]{1,2000}\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))\s{1,100}""",
    """\srt=({time}\d{1,100})""",
    """\sdestinationServiceName=({app}.+?)\s{1,100}\w+=""",
    """\srequestClientApplication=(|({user_agent}.+?))\s{1,100}\w+=""",
    """\sdvc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """exabeam_host=({host}[^\s]{1,2000})"""
  ]
}
```