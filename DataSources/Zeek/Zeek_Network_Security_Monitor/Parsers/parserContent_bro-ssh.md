#### Parser Content
```Java
{
Name = bro-ssh
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "ssh-login"
  TimeFormat = "epoch_sec"
  Conditions = [ "/ssh.log" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d{10})\.\d{6}\t({conn_id}[^\t]{1,2000})\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({src_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({dest_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|({version}[^\t]{1,2000}))\t(?:-|({outcome}[^\t]{1,2000}))\t(?:-|({auth_attempts}[^\t]{1,2000}))\t(?:-|({direction}[^\t]{1,2000}))\t(?:-|({client_ssh_version}[^\t]{1,2000}))\t(?:-|({server_ssh_version}[^\t]{1,2000}))\t(?:-|({cipher}[^\t]{1,2000}))\t(?:-|({mac_alg}[^\t]{1,2000}))\t(?:-|(none)|({compression_alg}[^\t]{1,2000}))\t(?:-|({kex_alg}[^\t]{1,2000}))\t(?:-|({host_key_alg}[^\t]{1,2000}))\t(?:-|({host_key}[^\t]{1,2000}))\t(?:-|({remote_location_country_code}[^\t]{1,2000}))\t(?:-|({remote_location_region}[^\t]{1,2000}))\t(?:-|({remote_location_city}[^\t]{1,2000}))\t(?:-|({remote_location_latitude}[^\t]{1,2000}))\t(?:-|({remote_location_longitude}[^\t]{1,2000}?))\s{0,100}$""",
    """({time}\d{10})\.\d{6}\t({conn_id}[^\t]{1,2000})\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({src_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({dest_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|({version}[^\t]{1,2000}))\t(?:-|({outcome}[^\t]{1,2000}))\t(?:-|({direction}[^\t]{1,2000}))\t(?:-|({client_ssh_version}[^\t]{1,2000}))\t(?:-|({server_ssh_version}[^\t]{1,2000}))\t(?:-|({cipher}[^\t]{1,2000}))\t(?:-|({mac_alg}[^\t]{1,2000}))\t(?:-|(none)|({compression_alg}[^\t]{1,2000}))\t(?:-|({kex_alg}[^\t]{1,2000}))\t(?:-|({host_key_alg}[^\t]{1,2000}))\t(?:-|({host_key}[^\t]{1,2000}))\t(?:-|({remote_location_country_code}[^\t]{1,2000}))\t(?:-|({remote_location_region}[^\t]{1,2000}))\t(?:-|({remote_location_city}[^\t]{1,2000}))\t(?:-|({remote_location_latitude}[^\t]{1,2000}))\t(?:-|({remote_location_longitude}[^\t]{1,2000}?))\s{0,100}$"""
  ]
}
```