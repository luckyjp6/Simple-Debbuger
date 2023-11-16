# Simple Instruction-level Debugger
此repo收錄課程「高等Unix」的大作業二。  
使用ptrace等工具實作簡易的debugger，稱為sdb。  

## Usage
使用方式類似常用debugger gdb：
```
./sdb <executable>
```

此repo使用反組譯工具capstone，sdb反組譯assembly language功能需安裝此工具方能顯示，若無安裝可能會看到如下畫面  

![image](https://github.com/luckyjp6/Simple-Debbuger/assets/96563567/c29e2c77-e47c-4cd8-8474-5b234f3100be)

## 實作功能
### Debugger基礎
- 實作細節：fork子程式，在子程式使用PTRACE_TRACEME，接著execvp出要追蹤的executable並給予其對應參數。
### 顯示反組譯後的指令
- 功能：顯示五個指令。  
    <img width="595" alt="image" src="https://github.com/luckyjp6/Simple-Debbuger/assets/96563567/233c91de-e967-488c-88eb-6bab4ee2c867">  
- 特殊情況：指令不足五個，僅顯示剩下的。  
    <img width="546" alt="image" src="https://github.com/luckyjp6/Simple-Debbuger/assets/96563567/4c54f82a-6535-4d79-a377-455219991442">  
- 實作細節：使用PTRACE_PEEKTEXT和暫存器rip的值將指令提取出，再使用capstone工具```cs_disasm```反組譯。

### si
- 功能：執行一個指令（一行asm code）。
- 實作細節：使用PTRACE_SINGLESTEP向前執行一個指令。

<img width="548" alt="image" src="https://github.com/luckyjp6/Simple-Debbuger/assets/96563567/f887ee59-f497-4185-8f33-8decd52218f7">

### cont
- 功能：向下執行直到碰到中斷點或程式結束。
- 實作細節：使用PTRACE_SINGLESTEP和PTRACE_CONT實作，輸入command有三種情形：程式剛開始、上一步是si或碰到中斷點，考慮最後一個情形，因程式很可能有迴圈等結構，不能直接使用PTRACE_CONT一路執行到下一個中斷點或程式結尾，需先以PTRACE_SINGLESTEP執行一步、恢復中斷點（如果有的話），然後才向下執行

### break
- 功能：設定中斷點。
- 實作細節：直接在將原本的指令替換成中斷指令0xcc，使用自定義結構保留原先指令。
- 相關影響及實作：
    - 顯示反組譯指令時，當偵測到0xcc，將其代換回原本的指令再進行後續反組譯與輸出，使用者不應看到debugger設置的中斷點。
    - 碰到中斷點後，須將其還原回原先指令，以利後續執行，執行完再重新寫為中斷點0xcc。
    - 針對碰到中斷點的處理和回復，```si```和```cont```的做法略有不同：執行完```si```後需檢查待執行指令是否為中斷點，如果是，需還原，避免```si```在同一個中斷點連續停留；執行完```cont```後須檢查剛執行完的最後一個指令是否為中斷點，如果是，需還原，因程式仍在執行，```cont```只可能因為中斷點停下，需還原碰到的中斷點，並將rip減一，然後重新執行（執行剛剛碰到的中斷點原本的指令）。

### anchor & timetravel
- 功能：anchor儲存當下程式狀態包括暫存器、stack和記憶體；timetravel將程式回溯到下anchor的狀態。
- 實作細節：使用PTRACE_GETREGS取得暫存器狀態、使用PTRACE_PEEKTEXT取得stack和記憶體內容；使用PTRACE_SETREGS重新設定暫存器狀態、使用PTRACE_POKETEXT重新寫入stack和記憶體內容。

e.g., 執行猜數字程式，利用anchor和timetravel重新猜答案。（第一次猜測非數字答案，是一個必錯的答案）
<img width="603" alt="image" src="https://github.com/luckyjp6/Simple-Debbuger/assets/96563567/40699abf-8807-41bd-91aa-18fb5fc2d618">
<img width="604" alt="image" src="https://github.com/luckyjp6/Simple-Debbuger/assets/96563567/23add8b3-1d9b-4f40-81fc-56e1c7555872">
