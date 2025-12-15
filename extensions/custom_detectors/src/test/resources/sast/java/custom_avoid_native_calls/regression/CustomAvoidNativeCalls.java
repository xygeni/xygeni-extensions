package com.reg.nat;

public class CustomAvoidNativeCalls {

  static{
    System.loadLibrary("CustomAvoidNativeCalls");
    Runtime.getRuntime().load("/opt/lib/CustomAvoidNativeCalls_base.so");
  }

  private native void print();
  private void noNativePrint() {}

  public static void main(String[] args) {
    CustomAvoidNativeCalls avnc = new CustomAvoidNativeCalls();
    avnc.print(); // FLAW
    avnc.noNativePrint();
  }
}
