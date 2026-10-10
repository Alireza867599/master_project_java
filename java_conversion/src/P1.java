/** Java implementation of auctioneer party P1; orchestration is shared with P0. */
public final class P1 {
    public static void main(String[] args) {
        try { AuctioneerParty.start(1,args); }
        catch(Exception e){System.err.println("P1 failed: "+e.getMessage());e.printStackTrace(System.err);System.exit(1);}
    }
}
