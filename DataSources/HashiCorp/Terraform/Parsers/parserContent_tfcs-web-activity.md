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
    """\s({host}[\w\-.]+)\s+TFCS_LOG\s+.*?({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+)\s+({src_ip}[A-Fa-f:\d.]+?):({src_port}\d+)\s+({user_email}[^\s@]+@[^\s@]+)\s+({result_code}\d+)\s+({bytes}\d+)\s+({method}\S+)\s+(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?[\\\/]*(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]+))(:({dest_port}\d+))?({uri_path}\/[^\s\?",]*)?({uri_query}\?[^"\s]*)?))\s+({action}[^\s]+)\s""",
    """\s+\d+\s+\d+\s+\S+\s+[^\s]*?({top_domain}[^\\\/\.\s":]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|be|gd|zip|to|live|mp|aws))+)(\/|:|")""",
  ]
  DupFields = [ "action->resource" ]
}
```