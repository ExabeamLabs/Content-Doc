#### Parser Content
```Java
{
Name = s-lanscopecat-web-activity
  Vendor = LanScope
  Product = LanScope Cat
  Lms = Splunk
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """LanScopeCat - WebAccess""", """URL=""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d\d:\d\d)\s{1,100}({host}\S+)\s{1,100}LanScopeCat\s{1,100}\-""",
    """\sEvent="({activity}[^"]+)""",
    """\sAgent="({dest_host}[^"]+)""",
    """\sLogonUser="({user}[^"]+)""",
    """\sURL="({full_url}(\w+:\/+)?({web_domain}[^\/"]+?)(:({dest_port}\d{1,100}))?({uri_path}\/[^"\?]*)?({uri_query}\?[^"]*)?)"""",
    """\sIPAddress="({src_ip}[a-fA-F\d.:]+)""",
    """\sURL="(\w+:\/+)?[^"\/]*?({top_domain}[^\."]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(:|\/|")""",
  ]
}
```