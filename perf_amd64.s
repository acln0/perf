#define SYS_IOCTL 16
#define PERF_EVENT_IOC_ENABLE  0x2400
#define PERF_EVENT_IOC_DISABLE 0x2401

TEXT ·doEnableRunDisable(SB),0,$0-16

  MOVQ fd+0(FP), DI
  MOVQ $PERF_EVENT_IOC_ENABLE, SI
  MOVQ $SYS_IOCTL, AX
  SYSCALL

                                   // Overhead:
  MOVQ f+8(FP), DX                 // 1
  MOVQ 0(DX), AX                   // 2
  CALL AX                          // 3, 4 (RET on the other side)

  MOVQ fd+0(FP), DI                // 5
  MOVQ $PERF_EVENT_IOC_DISABLE, SI // 6
  MOVQ $SYS_IOCTL, AX              // 7
  SYSCALL                          // 8

  RET
