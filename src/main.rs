#[cfg(feature = "cargo")]
mod realmain;

fn main() {


    #[cfg(feature = "cargo")]
    realmain::main();
 
    #[cfg(not(feature = "cargo"))]
    println!("Please enable feature cargo");
}
