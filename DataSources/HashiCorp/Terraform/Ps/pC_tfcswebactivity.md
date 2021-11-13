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
    """\s({host}[\w\-.]{1,2000})\s{1,100}TFCS_LOG\s{1,100}.*?({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})\s{1,100}({src_ip}[A-Fa-f:\d.]{1,2000}?):({src_port}\d{1,100})\s{1,100}({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})\s{1,100}({result_code}\d{1,100})\s{1,100}({bytes}\d{1,100})\s{1,100}({method}\S+)\s{1,100}(-|({full_url}(({protocol}[^:\\\/\s,"]{1,2000}):[\\\/]{1,2000})?[\\\/]{0,2000}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]{1,2000}))(:({dest_port}\d{1,100}))?({uri_path}\/[^\s\?",]{0,2000})?({uri_query}\?[^"\s]{0,2000})?))\s{1,100}({action}[^\s]{1,2000})\s""",
  ]
  DupFields = [ "action->resource" ]


}
```