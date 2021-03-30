#### Parser Content
```Java
{
Name = syslog-5156-ch
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "process-network"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    Conditions = [ " 5156 ", "篩選平台已經允許一個連線。" ]
    Fields = [ 
      """({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})""",
      """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[\-\+]\d\d:\d\d ({host}[\w.\-]+)\s""",
      """\d{2}:\d{2}:\d{2} ({dest_host}[\w.\-]+)\s""",
      """({event_code}5156)""",
      """處理程序識別碼:\s*({pid}\d+)""",
      """應用程式名稱:\s*({process}({directory}(?:[^\^]+)?[\\\/]+)?({process_name}[^\\\/\^]+?))\s+網路資訊:""",
      """來源位址:\s*({src_ip}[a-fA-F:\d.]+)""",
      """來源連接埠:\s*({src_port}\d+)""",
      """目的地位址:\s*({dest_ip}[a-fA-F:\d.]+)""",
      """目的地連接埠:\s*({dest_port}\d+)""",
      """通訊協定:\s*({ms_protocol_num}\d+)""",
      """階層名稱:\s*({layer_name}[^\s]+)""",
      """方向:\s*({direction}輸入|輸出)"""
    ]
    DupFields = ["directory->process_directory"]
  }
```