/** Java implementation of auctioneer party P0; orchestration is shared with P1. */
public final class P0 {
    public static void main(String[] args) {
        try { AuctioneerParty.start(0,args); }
        catch(Exception e){System.err.println("P0 failed: "+e.getMessage());e.printStackTrace(System.err);System.exit(1);}
    }
}
