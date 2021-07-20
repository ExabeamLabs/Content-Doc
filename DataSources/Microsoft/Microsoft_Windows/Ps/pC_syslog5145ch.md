#### Parser Content
```Java
{
Name = syslog-5145-ch
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    Conditions = [ " 5145 ", "已檢查網路共用物件，查看是否可授與用戶端想要的存取權。" ]
    Fields = [ 
      """({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3})""",
      """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[\-\+]\d\d:\d\d ({host}[\w.\-]{1,2000})\s""",
      """\d{2}:\d{2}:\d{2} ({dest_host}[\w.\-]{1,2000})\s""",
      """({event_code}5145)""",
      """\s安全性識別碼:\s{0,100}({user_sid}\S+)\s""",
      """\s帳戶名稱:\s{0,100}({user}[^\s]{1,2000})""",
      """\s帳戶網域:\s{0,100}({domain}[^\s]{1,2000})""",
      """\s登入識別碼:\s{0,100}({logon_id}[^\s]{1,2000})""",
      """\s物件類型:\s{0,100}({file_type}[^\s]{1,2000})""",
      """\s來源位址:\s{0,100}({src_ip}[a-fA-F:\d.]{1,2000})""",
      """\s來源連接埠:\s{0,100}({src_port}\d{1,100})""",
      """\s共用名稱:\s{0,100}(?:\\\\\*\\)?({share_name}.+?)\s{1,100}共用路徑:""",
      """\s共用路徑:\s{0,100}(?:[\\\?]{1,2000})?(?:\s{0,100}|({share_path}(({d_parent}.+?)\\)?({d_name}\s{0,100}\S[^\\]{1,2000}?))\\?\s{1,100})相對目標名稱:""",
      """\s相對目標名稱:\s{0,100}\\?(?:\s{0,100}|(?:({f_parent}.+?)\\)?({file_name}[^\\:\/]{1,2000}?(?:\.({file_ext}[^\.]{1,2000}?))?)(?:\\HEAD|:.+?|\\|\s)\s{0,100})存取要求資訊:""",
      """\s存取:\s{0,100}.*\s({accesses}SYNCHRONIZE|Execute|Traverse|Read|READ).*\s{0,100}存取檢查結果:""",
      """\s存取:\s{0,100}.*\s({accesses}WRITE_DAC|WRITE_OWNER|WriteAttributes|WriteEA).*\s{0,100}存取檢查結果:""",
      """\s存取:\s{0,100}.*\s({accesses}WriteData|AppendData).*\s{0,100}存取檢查結果:""",
      """\s存取:\s{0,100}.*\s({accesses}delete|Delete).*\s{0,100}存取檢查結果:""",
      """\s存取檢查結果:\s{0,100}({outcome}-)\s""",
      """\s存取檢查結果:\s{0,100}.*({outcome}授與).*"""
    ]
  }
```