#### Parser Content
```Java
{
Name = exchange-dlp-email-out-1
  Vendor = Microsoft
  Product = Exchange
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """archive[""", """ outbound """ ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """archive\[\d+\]:\s+({message_id}\S+)\s+({time}\d+).*?<({sender}.+?)>\s+({recipient}[^\s@]+@({external_domain}.+?))\s+\S+\s+({direction}outbound)"""
  ]
  DupFields = [ "recipient->recipients" ]
}
```