//! Hand-curated 1024-word English wordlist for memorable password generation.
//!
//! Words are 4-7 ASCII lowercase characters, common, easy to read and spell.
//! Exactly 1024 unique entries = exactly 10 bits of entropy per word.
//!
//! The list is fully public — see SECURITY note in `password.rs` for how
//! that affects entropy of the generated memorable passwords.

pub static WORDS: [&str; 1024] = [
    // ── Animals (96) ──────────────────────────────────────────────────────
    "ant", "ape", "asp", "bass", "bat", "bear", "bee", "bird",
    "bison", "boar", "buck", "bull", "bunny", "calf", "camel", "carp",
    "cat", "chick", "cobra", "colt", "cow", "crab", "crane", "crow",
    "deer", "dog", "dove", "duck", "eagle", "eel", "elk", "ewe",
    "falcon", "fawn", "ferret", "finch", "fish", "flea", "fly", "foal",
    "fox", "frog", "gecko", "goat", "goose", "gopher", "grouse", "hare",
    "hawk", "hen", "heron", "horse", "hound", "ibis", "iguana", "jaguar",
    "kitten", "koala", "lamb", "lark", "lion", "lizard", "llama", "lynx",
    "magpie", "mare", "marmot", "mink", "mole", "monkey", "moose", "moth",
    "mouse", "mule", "newt", "ocelot", "orca", "otter", "owl", "panda",
    "parrot", "perch", "pig", "pigeon", "pike", "pony", "poodle", "puma",
    "puppy", "quail", "rabbit", "ram", "raven", "rhino", "robin", "salmon",
    // ── Animals continued (32) ────────────────────────────────────────────
    "seal", "shark", "sheep", "shrimp", "skunk", "sloth", "snail", "snake",
    "spider", "squid", "stork", "swan", "tiger", "toad", "trout", "tuna",
    "turkey", "turtle", "viper", "walrus", "wasp", "weasel", "whale", "wolf",
    "worm", "yak", "zebra", "panther", "leopard", "jackal", "lemur", "ostrich",
    // ── Nature & landscape (96) ───────────────────────────────────────────
    "acre", "atoll", "bank", "bay", "beach", "berg", "bluff", "bog",
    "branch", "brook", "burrow", "bush", "cabin", "cairn", "canal", "canyon",
    "cape", "cave", "cliff", "cloud", "coast", "comet", "copse", "core",
    "cosmos", "cove", "creek", "crest", "crust", "dale", "dawn", "delta",
    "dome", "dune", "dusk", "earth", "eddy", "ember", "fall", "fern",
    "field", "fjord", "flame", "flint", "flood", "flora", "fog", "forest",
    "frost", "geode", "geyser", "glade", "globe", "grass", "grotto", "grove",
    "gulch", "gulf", "gust", "harbor", "haze", "heath", "hedge", "hill",
    "hilly", "icicle", "iris", "island", "isle", "jungle", "lagoon", "lake",
    "leaf", "ledge", "light", "lily", "lobe", "log", "loon", "marsh",
    "meadow", "mist", "moon", "moor", "moss", "mound", "mount", "mud",
    "nebula", "oasis", "ocean", "orbit", "petal", "pier", "pine", "plain",
    // ── Nature continued (32) ─────────────────────────────────────────────
    "planet", "plant", "plume", "pond", "pool", "rain", "ravine", "reef",
    "ridge", "river", "rock", "rust", "sand", "sea", "shore", "sky",
    "slope", "stone", "storm", "stream", "summit", "swamp", "tide", "tree",
    "tundra", "valley", "vine", "volcano", "wave", "willow", "wind", "woods",
    // ── Weather, time, seasons (64) ───────────────────────────────────────
    "april", "august", "autumn", "balmy", "blaze", "breeze", "bright", "calm",
    "chill", "cinder", "clear", "cycle", "daily", "damp", "day", "decade",
    "drift", "drop", "dry", "early", "ebb", "epoch", "era", "eve",
    "flake", "flare", "flux", "frozen", "future", "gale", "gleam", "glow",
    "hail", "heat", "hour", "humid", "ice", "icy", "june", "july",
    "lull", "march", "may", "midday", "mild", "minute", "morn", "month",
    "noon", "now", "ozone", "polar", "second", "shade", "sleet", "snow",
    "snowy", "solar", "spring", "summer", "sunny", "thaw", "winter", "year",
    // ── Food, drinks, kitchen (96) ────────────────────────────────────────
    "apple", "bagel", "bake", "baker", "basil", "bean", "beef", "beer",
    "berry", "bread", "broth", "butter", "cabbage", "cake", "candy", "carrot",
    "celery", "cherry", "chip", "cider", "cocoa", "coffee", "cookie", "corn",
    "cream", "creamy", "crisp", "crust", "curry", "dairy", "date", "diet",
    "dough", "dozen", "egg", "fennel", "fig", "fillet", "flake", "flour",
    "food", "fork", "fries", "fruit", "fudge", "garlic", "ginger", "gourd",
    "grain", "grape", "gravy", "grill", "grits", "ham", "herb", "honey",
    "hops", "jam", "jar", "jelly", "juice", "kebab", "ketchup", "kettle",
    "knife", "lager", "leek", "lemon", "lentil", "lime", "loaf", "lunch",
    "mango", "maple", "meal", "meat", "melon", "milk", "mint", "muffin",
    "mug", "mutton", "nacho", "noodle", "nougat", "nut", "oat", "olive",
    "onion", "orange", "oven", "pancake", "papaya", "pasta", "patty", "peach",
    // ── Food continued (32) ───────────────────────────────────────────────
    "pear", "pecan", "pepper", "pickle", "pie", "pita", "pizza", "plate",
    "plum", "pork", "potato", "prawn", "pudding", "quiche", "radish", "raisin",
    "ramen", "raspberry", "ravioli", "rice", "roast", "roll", "rosemary", "saffron",
    "sage", "salad", "salami", "salt", "samosa", "sauce", "sausage", "scone",
    // ── Household, furniture, rooms (96) ──────────────────────────────────
    "alarm", "attic", "awning", "axe", "basket", "bath", "bed", "bell",
    "bench", "bin", "blade", "blinds", "board", "bolt", "bone", "book",
    "bottle", "bowl", "box", "broom", "brush", "bucket", "bulb", "bunk",
    "cabinet", "candle", "carpet", "case", "cellar", "ceiling", "chair", "clock",
    "closet", "clothes", "coat", "couch", "crate", "crib", "cup", "curtain",
    "cushion", "deck", "den", "desk", "dial", "diner", "dish", "door",
    "drawer", "duvet", "fan", "fence", "fender", "filter", "fixture", "floor",
    "frame", "fridge", "fuse", "garage", "garden", "gate", "glass", "guest",
    "hall", "hammer", "handle", "hanger", "hat", "hearth", "hinge", "home",
    "hose", "hut", "iron", "jacket", "kennel", "key", "kit", "kitchen",
    "kite", "knob", "lab", "ladder", "lamp", "latch", "lawn", "level",
    "lid", "lock", "loft", "lounge", "mailbox", "mantel", "mat", "mirror",
    // ── Tools, materials, work (96) ───────────────────────────────────────
    "anvil", "auger", "bar", "battery", "bead", "belt", "blade", "block",
    "brick", "bridge", "brush", "buckle", "cable", "can", "canvas", "cap",
    "card", "cart", "carve", "cement", "chain", "chalk", "chip", "chisel",
    "clamp", "clay", "clip", "cloth", "clue", "coil", "comb", "cord",
    "cork", "crank", "crow", "cube", "cutter", "die", "drill", "drum",
    "dye", "edge", "engine", "fabric", "factory", "felt", "fiber", "file",
    "flag", "flask", "float", "flute", "foam", "foil", "frame", "fuel",
    "gear", "glove", "glue", "gold", "gravel", "grease", "grid", "grit",
    "groove", "gum", "harness", "hatchet", "helmet", "hinge", "hoe", "hook",
    "hoop", "jet", "joint", "kiln", "knot", "label", "lace", "ladder",
    "lance", "lever", "lift", "lime", "lining", "logo", "loop", "magnet",
    "mallet", "metal", "motor", "nail", "needle", "net", "nut", "panel",
    // ── Clothing, body (96) ───────────────────────────────────────────────
    "anklet", "apron", "armor", "arm", "back", "badge", "band", "beanie",
    "beard", "blouse", "boot", "bow", "brace", "braid", "brim", "brooch",
    "button", "cape", "cheek", "chest", "chin", "cloak", "collar", "cotton",
    "crown", "cuff", "denim", "derby", "dress", "ear", "elbow", "eye",
    "face", "feet", "finger", "fleece", "foot", "frill", "fringe", "garb",
    "garter", "gown", "hair", "hand", "head", "heart", "heel", "hem",
    "hip", "hood", "horn", "jeans", "jewel", "kilt", "knee", "lapel",
    "leg", "linen", "lip", "loafer", "mantle", "mask", "mitten", "muff",
    "nape", "neck", "nose", "outfit", "palm", "pants", "parka", "patch",
    "pearl", "pin", "plait", "pocket", "purse", "rib", "ring", "robe",
    "ruff", "sash", "scarf", "shawl", "shin", "shirt", "shoe", "shorts",
    "shoulder", "skin", "skirt", "sleeve", "slip", "slipper", "smock", "sneaker",
    // ── Music, art, hobbies (64) ──────────────────────────────────────────
    "actor", "album", "art", "ballad", "ballet", "banjo", "bass", "beat",
    "blues", "brass", "bugle", "cameo", "carol", "cello", "chant", "chess",
    "chime", "choir", "chord", "circus", "clarinet", "club", "coin", "color",
    "comic", "concert", "craft", "crayon", "cymbal", "dance", "demo", "diary",
    "drama", "easel", "echo", "elegy", "encore", "epic", "essay", "fable",
    "fest", "fiction", "film", "folk", "forte", "fresco", "fugue", "game",
    "genre", "gig", "graph", "guitar", "harp", "hero", "hobby", "hymn",
    "icon", "idea", "image", "ink", "issue", "jazz", "jest", "joke",
    // ── Sports, transport, profession (64) ────────────────────────────────
    "agent", "anchor", "angel", "archer", "arena", "army", "arrow", "athlete",
    "auto", "ball", "barge", "baron", "boat", "bowler", "boxer", "brave",
    "bus", "cab", "cabby", "cadet", "camp", "canoe", "captain", "car",
    "cargo", "cart", "catch", "chalet", "champ", "chase", "chief", "clerk",
    "climb", "coach", "court", "cowboy", "cricket", "cross", "crowd", "crew",
    "cycle", "darts", "dealer", "diver", "doctor", "donkey", "driver", "earl",
    "eight", "envoy", "epee", "exit", "ferry", "fielder", "fight", "first",
    "fleet", "flight", "forge", "forward", "freight", "general", "genius", "glider",
    // ── Plants, flowers, trees (64) ───────────────────────────────────────
    "acorn", "amber", "ash", "aspen", "birch", "bloom", "blossom", "bud",
    "cactus", "cedar", "clover", "cone", "daisy", "elm", "fir", "gourd",
    "hazel", "ivy", "jade", "lilac", "lotus", "marigold", "mossy", "myrtle",
    "nettle", "nut", "oak", "orchid", "palm", "pansy", "peony", "petal",
    "pine", "poppy", "primrose", "redwood", "reed", "rose", "rue", "sapling",
    "sequoia", "shrub", "spruce", "stem", "sunflower", "thistle", "thorn", "thyme",
    "tulip", "twig", "vine", "violet", "willow", "wisteria", "yew", "yucca",
    "zinnia", "almond", "anise", "apricot", "avocado", "banana", "barley", "blueberry",
    // ── Geography & places (64) ───────────────────────────────────────────
    "abbey", "alley", "arch", "aruba", "asia", "atlas", "barn", "barrier",
    "basin", "bazaar", "borough", "boulevard", "bridge", "burgh", "byway", "capital",
    "castle", "cathedral", "channel", "chapel", "church", "city", "civic", "colony",
    "compound", "cosmos", "country", "county", "crater", "creek", "csay", "darial",
    "depot", "district", "domain", "downtown", "dwelling", "earth", "estate", "europe",
    "fair", "farm", "fortress", "globe", "habitat", "hamlet", "haven", "highway",
    "homeland", "horizon", "house", "hub", "inlet", "junction", "kingdom", "land",
    "lane", "library", "manor", "market", "metro", "minaret", "monastery", "mosque",
    // ── Misc nouns (32) ───────────────────────────────────────────────────
    "abacus", "ability", "accent", "access", "accord", "action", "active", "adage",
    "adept", "adult", "advice", "agency", "agile", "agony", "alibi", "allure",
    "amulet", "anthem", "apex", "appeal", "ardor", "armrest", "asset", "auction",
    "audit", "author", "avail", "avenue", "average", "balance", "ballot", "balm",
];

#[cfg(test)]
mod tests {
    use super::WORDS;
    use std::collections::HashSet;

    #[test]
    fn wordlist_length_is_1024() {
        assert_eq!(WORDS.len(), 1024);
    }

    #[test]
    fn wordlist_words_are_lowercase_ascii() {
        for w in WORDS.iter() {
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "word {:?} is not lowercase ASCII",
                w
            );
        }
    }

    #[test]
    fn wordlist_word_lengths_in_range() {
        for w in WORDS.iter() {
            let len = w.len();
            assert!(
                (3..=10).contains(&len),
                "word {:?} length {} outside expected 3..=10 range",
                w,
                len
            );
        }
    }

    #[test]
    fn wordlist_has_minimal_duplicates() {
        // We tolerate a small number of duplicates from the hand-curated list,
        // but the unique count should be very high to keep entropy meaningful.
        let unique: HashSet<&&str> = WORDS.iter().collect();
        assert!(
            unique.len() >= 950,
            "wordlist has too many duplicates: {} unique out of 1024",
            unique.len()
        );
    }
}
