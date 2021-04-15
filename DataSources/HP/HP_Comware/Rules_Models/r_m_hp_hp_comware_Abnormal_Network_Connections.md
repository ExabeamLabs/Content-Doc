Vendor: HP
==========
### Product: [HP Comware](../ds_hp_hp_comware.md)
### Use-Case: [Abnormal Network Connections](../../../../UseCases/uc_abnormal_network_connections.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   0    |     2      |      1      |    1    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                                                                               | Models |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-created | <b>T1047 - Windows Management Instrumentation</b><b>T1175 - T1175</b><br> ↳ <b>A-Impacket-Lateral-Detection</b>: Activity related to Impacket framework using wmiexec, dcomexe, or smbexec processes via command line have been found on this asset.<br> ↳ <b>Impacket-Lateral-Detection</b>: Activity related to Impacket framework using wmiexec, dcomexe, or smbexec processes via command line have been found. |        |