#### Parser Content
```Java
{
Name = trend-micro-alert-6
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ WFBSS-SVC-AC [LogUrlFiltering""" ]
  Fields = [
    """({host}\S+) WFBSS-SVC-AC""",
    """\d{1,100} ({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d) \d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100}""",
    """Device name="({src_host}[^"]{1,2000})""",
    """User="({user}[^"]{1,2000})""",
    """URL="({malware_url}[^"]{1,2000})""",
    """URL="(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\s|\/|$))[^\s\/]{1,2000})""",
    """\[({alert_type}[^@]{1,2000})""",
  ]
  DupFields = [ "top_domain->alert_name" ]
}
```