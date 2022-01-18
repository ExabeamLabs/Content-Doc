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
      """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[\-\+]\d\d:\d\d ({host}[\w.\-]{1,2000})\s""",
      """\d{2}:\d{2}:\d{2} ({dest_host}[\w.\-]{1,2000})\s""",
      """({event_code}5156)""",
      """處理程序識別碼:\s{0,100}({pid}\d{1,100})""",
      """應用程式名稱:\s{0,100}({process}({directory}(?:[^\^]{1,2000})?[\\\/]{1,2000})?({process_name}[^\\\/\^]{1,2000}?))\s{1,100}網路資訊:""",
      """來源位址:\s{0,100}({src_ip}[a-fA-F:\d.]{1,2000})""",
      """來源連接埠:\s{0,100}({src_port}\d{1,100})""",
      """目的地位址:\s{0,100}({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """目的地連接埠:\s{0,100}({dest_port}\d{1,100})""",
      """通訊協定:\s{0,100}({ms_protocol_num}\d{1,100})""",
      """階層名稱:\s{0,100}({layer_name}[^\s]{1,2000})""",
      """方向:\s{0,100}({direction}輸入|輸出)"""
    ]
    DupFields = ["directory->process_directory"]
  

}
```