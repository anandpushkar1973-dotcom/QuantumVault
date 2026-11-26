use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData,
    ReplyDirectory, ReplyEntry, Request,
};
use libc::ENOENT;
use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);
const HELLO_CONTENT: &str = "Hello World\n";

fn dir_attr() -> FileAttr {
    FileAttr {
        ino: 1, size: 0, blocks: 0,
        atime: UNIX_EPOCH, mtime: UNIX_EPOCH, ctime: UNIX_EPOCH, crtime: UNIX_EPOCH,
        kind: FileType::Directory, perm: 0o755, nlink: 2,
        uid: 1000, gid: 1000, rdev: 0, flags: 0, blksize: 512,
    }
}

fn file_attr() -> FileAttr {
    FileAttr {
        ino: 2, size: HELLO_CONTENT.len() as u64, blocks: 1,
        atime: UNIX_EPOCH, mtime: UNIX_EPOCH, ctime: UNIX_EPOCH, crtime: UNIX_EPOCH,
        kind: FileType::RegularFile, perm: 0o644, nlink: 1,
        uid: 1000, gid: 1000, rdev: 0, flags: 0, blksize: 512,
    }
}

struct VaultFS;

impl Filesystem for VaultFS {
    // Koi naam dhoondhna (jaise ls ya cat karte waqt)
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == 1 && name.to_str() == Some("hello.txt") {
            reply.entry(&TTL, &file_attr(), 0);
        } else {
            reply.error(ENOENT);
        }
    }

    // File/folder ki jaankari (size, permissions)
    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match ino {
            1 => reply.attr(&TTL, &dir_attr()),
            2 => reply.attr(&TTL, &file_attr()),
            _ => reply.error(ENOENT),
        }
    }

    // File ka content padhna
    fn read(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64, _size: u32,
            _flags: i32, _lock: Option<u64>, reply: ReplyData) {
        if ino == 2 {
            reply.data(&HELLO_CONTENT.as_bytes()[offset as usize..]);
        } else {
            reply.error(ENOENT);
        }
    }

    // Folder ke andar ki list (ls ke liye)
    fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64,
               mut reply: ReplyDirectory) {
        if ino != 1 {
            reply.error(ENOENT);
            return;
        }
        let entries = [
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (2, FileType::RegularFile, "hello.txt"),
        ];
        for (i, e) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(e.0, (i + 1) as i64, e.1, e.2) {
                break;
            }
        }
        reply.ok();
    }
}

fn main() {
    let mountpoint = std::env::args().nth(1).expect("Usage: fuse-vault <mountpoint>");
    let options = vec![MountOption::RO, MountOption::FSName("quantumvault".to_string())];
    fuser::mount2(VaultFS, mountpoint, &options).unwrap();
}