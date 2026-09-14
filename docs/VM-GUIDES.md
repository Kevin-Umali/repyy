# Manual isolation guides

The built-in backend is Docker. These are manual workflows for users who need a VM boundary today;
they do not enable `--sandbox=vm` or `--sandbox=auto`, which are reserved for a later release.

Copy the repository into the guest or expose it as a read-only share. Write only the report to a
narrow output directory, copy that report out, and destroy the guest or discard its snapshot
afterward. A VM is a manual workflow; repyy does not create or manage the guest.

Before starting, install repyy in the guest and run `repyy version`. For local analysis, disable
guest networking before attaching the repository. Do not open the repository in an IDE, install its
dependencies, or run its build scripts before the scan.

## Windows Sandbox

Windows Sandbox is available on supported Pro, Enterprise, and Education editions; Windows Home does
not include it. See
[Microsoft's requirements](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/).
Enable **Windows Sandbox** from “Turn Windows features on or off”. Create `C:\review\input\repo` and
`C:\review\output` on the host, put the repository under `repo`, and put `repyy.exe` in
`C:\review\input` before starting the sandbox. Save the following as `repyy-review.wsb`, then
double-click that file. It maps a dedicated input folder read-only and a separate output folder
read-write:

```xml
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\review\input</HostFolder>
      <SandboxFolder>C:\review\input</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>C:\review\output</HostFolder>
      <SandboxFolder>C:\review\output</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <Networking>Disable</Networking>
</Configuration>
```

Put the repository in `C:\review\input\repo`. Inside the sandbox, run:

```powershell
& C:\review\input\repyy.exe version
& C:\review\input\repyy.exe scan C:\review\input\repo --format html --output C:\review\output\report.html
```

Do not map credentials, SSH directories, package caches, or a broad home directory. Close the
sandbox when finished; its writable state is discarded.

## macOS with UTM

Create a disposable Linux VM in [UTM](https://docs.getutm.app/). Install the Linux release of
`repyy` in the guest before introducing the repository. In the VM settings, remove the Network
device for the analysis run; a host-only network still permits guest-to-host traffic. Attach only a
dedicated input directory or read-only disk image, and mount it read-only inside the guest. UTM
documents its
[Linux directory sharing options](https://docs.getutm.app/guest-support/sharing/directory/); check
the guest mount flags before scanning.

Run the scan inside the guest, writing to its own private disk:

```sh
repyy scan /mnt/review --format html --output "$HOME/report.html"
```

The share should be read-only; the report path is on the guest's writable home disk. Copy out only
the finished report after the scan.

After scanning, shut down the guest and export only `report.html` through a separate temporary
output disk or explicit copy step. Open it on the host. Delete the disposable VM after reviewing the
result.

For a remote HTTPS URL, use a separate networked fetch VM and transfer only its checkout to this
network-disabled analysis VM. Do not forward credentials or a host Git configuration into the
analysis guest.

## Linux with QEMU/KVM

Create a disposable QEMU/KVM guest with your distribution's normal cloud image or VM tooling. Attach
a dedicated repository directory as a read-only 9p, virtiofs, or ISO share and keep report output on
a separate writable share.

```sh
repyy scan /mnt/review --format html --output /mnt/output/report.html
```

Keep `/mnt/output` separate and writable, then shut down the guest and remove its temporary disk or
snapshot after exporting the report.

Use a network-disabled guest for local analysis. For an HTTPS remote, clone it in a disposable
networked guest, shut that guest down, and transfer only the checkout into the analysis guest. Do
not attach the host Docker socket, home directory, SSH agent, or package-manager cache.
