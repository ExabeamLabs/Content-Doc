#### Parser Content
```Java
{
Name = tfcs-web-activity
  Vendor = HashiCorp
  Product = Terraform
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """ TFCS_LOG """ ]
  Fields = [
    """\s({host}[\w\-.]+)\s{1,100}TFCS_LOG\s{1,100}.*?({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})\s{1,100}({src_ip}[A-Fa-f:\d.]+?):({src_port}\d{1,100})\s{1,100}({user_email}[^\s@]+@[^\s@]+)\s{1,100}({result_code}\d{1,100})\s{1,100}({bytes}\d{1,100})\s{1,100}({method}\S+)\s{1,100}(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?[\\\/]*(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]+))(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?",]*)?({uri_query}\?[^"\s]*)?))\s{1,100}({action}[^\s]+)\s""",
    """\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\S+\s{1,100}[^\s]*?({top_domain}[^\\\/\.\s":]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|be|gd|zip|to|live|mp|aws))+)(\/|:|")""",
  ]
  DupFields = [ "action->resource" ]
}
```