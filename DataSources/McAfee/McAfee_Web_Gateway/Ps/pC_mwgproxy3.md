#### Parser Content
```Java
{
Name = mwg-proxy-3
    Vendor = McAfee
    Product = McAfee Web Gateway
    Lms = Direct
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
    Conditions = [ """mwg: [""", """);""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """mwg: \[({time}\d{1,100}/\w+/\d\d\d\d:\d\d:\d\d:\d\d (\+|\-)\d{1,100})\];\s{0,100}(|-|({user}[^;]{1,2000}?));\s{0,100}(|({result_code}\d{1,100}));\s{0,100}(|({src_ip}[a-fA-F\d.:]{1,2000}));\s{0,100}(|({dest_ip}[a-fA-F\d.:]{1,2000}));\s{0,100}(|\(({web_domain}[^;]{1,2000}?)\));\s{0,100}(|\(-\)|\(({referrer}[^;]{1,2000}?)\));\s{0,100}(|\(({categories}({category}[^,;]{1,2000})[^;]{0,2000}?)\));\s{0,100}(|({risk_level}[^;]{1,2000}?));\s{0,100}(|({mime}[^;]{1,2000}?));\s{0,100}(|({bytes_in}\d{1,100}));\s{0,100}(|({bytes_out}\d{1,100}));\s{0,100}(|-|({rule}[^;]{1,2000}?));\s{0,100}(|({failure_reason}[^;]{1,2000}?));([^;]{0,2000};){2}\s{0,100}(|\(({method}\w+)\s{1,100}({full_url}(\w+:/+)?[^;\/]{0,2000}?((?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s;]{1,2000}(?:\.)+)?(:({dest_port}\d{1,100}))?({uri_path}/[^;\?]{0,2000}?)?({uri_query}\?[^;]{0,2000}?)?)\s{1,100}\S+\));\s{0,100}(|({protocol}[^;]{1,2000}?));\s{0,100}(|({user_agent}[^;]{1,2000}?))(;|\s{0,100}$)""",
    ]
  

}
```