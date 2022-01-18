#### Parser Content
```Java
{
Name = cef-aws-netflow-connection
  Vendor = Amazon
  Product = AWS CloudWatch
  Lms = ArcSight
  DataType = "netflow-connection"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|""", """ eni-""", """requestClientApplication=AWS-FlowLogs""" ]
  Fields = [
    """cs6=\d{1,100}\s{1,100}(unknown|({account_id}\S+))\s{1,100}({interface_id}\S+)\s{1,100}(-|({src_ip}[A-Fa-f:\d.]{1,2000}))\s{1,100}(-|({dest_ip}[A-Fa-f:\d.]{1,2000}))\s{1,100}(-|({src_port}\d{1,100}))\s{1,100}(-|({dest_port}\d{1,100}))\s{1,100}(-|({protocol}\S+))\s{1,100}(-|({packets}\S+))\s{1,100}(-|({bytes}\d{1,100}))\s{1,100}({time}\d{1,100})\s{1,100}\S+\s{1,100}(-|({action}\S+))\s{1,100}(-|({outcome}\S+))""",
  ]


}
```