#### Parser Content
```Java
{
Name = hp-ndcl-process-created
    Vendor = HP
  Product = HP Comware
    Lms = Direct
    DataType = "process-created"
    TimeFormat = "MMM dd HH:mm:ss yyyy"
    Conditions = [ """-User=""", """-Task=""", """Source: /""", """TAG:""", """Command is""", """-IPAddr=""" ]
    Fields = [
      """({time}\w{3}\s{1,100}\d{1,2}\s{1,100}\d{2}:\d{2}:\d{2}\s{1,100}\d{4})\s{1,100}({host}[^\s]{1,2000})\s{1,100}%%""",
      """-User=({user}[^;]{1,2000});""",
      """-IPAddr=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """-DevIP=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """Command\s{0,100}is\s{0,100}({process}(?:({directory}.+?)[\\\/]{1,2000})?({process_name}[^\s\\\/]{1,2000}))\s{0,100}Source:""",
      """Command\s{0,100}is\s{0,100}({command_line}.+?)\s{0,100}Source:"""
    ]
    DupFields = [ "host->dest_host" ]
  }
```