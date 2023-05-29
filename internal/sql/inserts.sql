INSERT INTO "public"."authors"("author_name","created_at","updated_at")
VALUES
(E'Stephen King',E'2022-02-21 00:00:00',E'2022-02-21 00:00:00'),
(E'Mark Twain',E'2022-02-21 00:00:00',E'2022-02-21 00:00:00');


INSERT INTO "public"."genres"("genre_name","created_at","updated_at")
VALUES
(E'Science Fiction',E'2022-02-13 00:00:00',E'2022-02-13 00:00:00'),
(E'Fantasy',E'2022-02-13 00:00:00',E'2022-02-13 00:00:00'),
(E'Romance',E'2022-02-13 00:00:00',E'2022-02-13 00:00:00'),
(E'Thriller',E'2022-02-13 00:00:00',E'2022-02-13 00:00:00'),
(E'Mystery',E'2022-02-13 00:00:00',E'2022-02-13 00:00:00'),
(E'Horror',E'2022-02-13 00:00:00',E'2022-02-13 00:00:00'),
(E'Classic',E'2022-02-13 00:00:00',E'2022-02-13 00:00:00');


INSERT INTO "public"."books"("title","author_id","publication_year","created_at","updated_at","slug","description")
VALUES
(E'The Shining',1,1977,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00',E'the-shining',E'Jack Torrance, his wife Wendy, and their young son Danny move into the Overlook Hotel, where Jack has been hired as the winter caretaker. Cut off from civilization for months, Jack hopes to battle alcoholism and uncontrolled rage while writing a play. Evil forces residing in the Overlook – which has a long and violent history – covet young Danny for his precognitive powers and exploit Jack’s weaknesses to try to claim the boy.'),
(E'\'Salem\'s Lot',1,1975,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00',E'salems-lot',E'Author Ben Mears returns to ‘Salem\'s Lot to write a book about a house that has haunted him since childhood only to find his isolated hometown infested with vampires. While the vampires claim more victims, Mears convinces a small group of believers to combat the undead.'),
(E'The Stand',1,1979,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00',E'the-stand',E'One man escapes from a biological weapon facility after an accident, carrying with him the deadly virus known as Captain Tripps, a rapidly mutating flu that - in the ensuing weeks - wipes out most of the world\'s population. In the aftermath, survivors choose between following an elderly black woman to Boulder or the dark man, Randall Flagg, who has set up his command post in Las Vegas. The two factions prepare for a confrontation between the forces of good and evil.'),
(E'The Gunslinger',1,1982,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00',E'the-gunslinger',E'The opening chapter in the epic Dark Tower series. Roland, the last gunslinger, in a world where time has moved on, pursues his nemesis, The Man in Black, across a desert. Roland\'s ultimate goal is the Dark Tower, the nexus of all universes. This mysterious icon\'s power is failing, threatening everything in existence. '),
(E'IT',1,1986,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00',E'it',E' A promise made twenty-eight years ago calls seven adults to reunite in Derry, Maine, where as teenagers they battled an evil creature that preyed on the city\'s children. Unsure that their Losers Club had vanquished the creature all those years ago, the seven had vowed to return to Derry if IT should ever reappear. Now, children are being murdered again and their repressed memories of that summer return as they prepare to do battle with the monster lurking in Derry\'s sewers once more.'),
(E'The Dead Zone',1,1979,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00',E'the-dead-zone',E'Waking up from a five-year coma after a car accident, former schoolteacher Johnny Smith discovers that he can see people\'s futures and pasts when he touches them. Many consider his talent a gift; Johnny feels cursed. His fiance married another man during his coma and people clamor for him to solve their problems. When Johnny has a disturbing vision after he shakes the hand of an ambitious and amoral politician, he must decide if he should take drastic action to change the future.');


INSERT INTO "public"."books_genres"("book_id","genre_id","created_at","updated_at")
VALUES
(1,6,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00'),
(1,4,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00'),
(2,6,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00'),
(3,2,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00'),
(3,6,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00'),
(4,4,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00'),
(5,4,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00'),
(6,6,E'2022-02-21 00:00:00',E'2022-02-21 00:00:00');
