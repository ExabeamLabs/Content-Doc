#### Parser Content
```Java
{
Name = cef-aws-netflow-connection
  Vendor = AWS
  Product = AWS CloudWatch
  Lms = ArcSight
  DataType = "netflow-connection"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|""", """ eni-""", """requestClientApplication=AWS-FlowLogs""" ]
  Fields = [
    """({host}[\w\-.]+)\s+Skyformation""",
    """cs6=\d+\s+(unknown|({account_id}\S+))\s+({interface_id}\S+)\s+(-|({src_ip}[A-Fa-f:\d.]+))\s+(-|({dest_ip}[A-Fa-f:\d.]+))\s+(-|({src_port}\d+))\s+(-|({dest_port}\d+))\s+(-|({protocol}\S+))\s+(-|({packets}\S+))\s+(-|({bytes}\d+))\s+({time}\d+)\s+\S+\s+(-|({action}\S+))\s+(-|({outcome}\S+))""",
  ]
}
```